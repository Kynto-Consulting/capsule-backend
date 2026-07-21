package handlers

import (
	"context"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/kynto/capsule/backend/internal/domain"
)

// provisionDomainSSL drives the ACM + ALB wiring for a custom domain:
//  1. Ensures an ACM cert (DNS-validated) exists for the domain.
//  2. Returns the ACM validation CNAME so the caller can surface it (the user
//     must add it in external-DNS mode).
//  3. Once the cert is ISSUED, attaches it to the ALB HTTPS listener and adds
//     host-header rules (443 + 80) forwarding the domain to the backend target
//     group, whose proxy middleware routes by Host to the right project.
//
// Returns (sslEnabled, validationRecord, error). validationRecord is
// "CNAME <name> -> <value>" for display; empty once no longer needed.
func (h *DomainHandler) provisionDomainSSL(ctx context.Context, d *domain.Domain) (bool, string, error) {
	if h.aws == nil || h.aws.ACM == nil || h.aws.ELBV2 == nil {
		return false, "", fmt.Errorf("aws clients not configured")
	}

	certARN, err := h.ensureACMCert(ctx, d.DomainName)
	if err != nil {
		return false, "", fmt.Errorf("ensure acm cert: %w", err)
	}

	desc, err := h.aws.ACM.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
		CertificateArn: aws.String(certARN),
	})
	if err != nil {
		return false, "", fmt.Errorf("describe cert: %w", err)
	}
	cert := desc.Certificate

	// Extract the DNS validation record (for the user to add in external DNS).
	validation := ""
	for _, vo := range cert.DomainValidationOptions {
		if vo.ResourceRecord != nil {
			name := strings.TrimSuffix(aws.ToString(vo.ResourceRecord.Name), ".")
			val := strings.TrimSuffix(aws.ToString(vo.ResourceRecord.Value), ".")
			validation = fmt.Sprintf("CNAME %s -> %s", name, val)
			break
		}
	}

	if cert.Status != acmtypes.CertificateStatusIssued {
		// Not validated yet — user needs to add the validation CNAME.
		return false, validation, nil
	}

	// Cert issued → wire the ALB: attach cert + add host rules to backend TG.
	if err := h.wireALBForDomain(ctx, d.DomainName, certARN); err != nil {
		return false, validation, fmt.Errorf("wire alb: %w", err)
	}
	return true, "", nil
}

// ensureACMCert returns the ARN of an ACM cert for domainName, requesting a new
// DNS-validated cert if none exists.
func (h *DomainHandler) ensureACMCert(ctx context.Context, domainName string) (string, error) {
	// Look for an existing (non-failed) cert for this exact domain.
	var token string
	for {
		out, err := h.aws.ACM.ListCertificates(ctx, &acm.ListCertificatesInput{
			MaxItems:  aws.Int32(100),
			NextToken: nilIfEmpty(token),
		})
		if err != nil {
			return "", err
		}
		for _, c := range out.CertificateSummaryList {
			if strings.EqualFold(aws.ToString(c.DomainName), domainName) {
				return aws.ToString(c.CertificateArn), nil
			}
		}
		if out.NextToken == nil {
			break
		}
		token = aws.ToString(out.NextToken)
	}

	// None found — request a new DNS-validated cert.
	req, err := h.aws.ACM.RequestCertificate(ctx, &acm.RequestCertificateInput{
		DomainName:       aws.String(domainName),
		ValidationMethod: acmtypes.ValidationMethodDns,
		Tags: []acmtypes.Tag{
			{Key: aws.String("managed-by"), Value: aws.String("capsule")},
		},
	})
	if err != nil {
		return "", err
	}
	return aws.ToString(req.CertificateArn), nil
}

// wireALBForDomain attaches the cert to the HTTPS listener and ensures
// host-header rules on both listeners forward the domain to the backend TG.
func (h *DomainHandler) wireALBForDomain(ctx context.Context, domainName, certARN string) error {
	lbARN, err := h.findLoadBalancerARN(ctx)
	if err != nil {
		return err
	}
	backendTG, err := h.findTargetGroupARN(ctx, "capsule-backend")
	if err != nil {
		return err
	}

	listeners, err := h.aws.ELBV2.DescribeListeners(ctx, &elbv2.DescribeListenersInput{
		LoadBalancerArn: aws.String(lbARN),
	})
	if err != nil {
		return err
	}

	var httpsListener, httpListener string
	for _, l := range listeners.Listeners {
		switch aws.ToInt32(l.Port) {
		case 443:
			httpsListener = aws.ToString(l.ListenerArn)
		case 80:
			httpListener = aws.ToString(l.ListenerArn)
		}
	}

	// Attach cert to the HTTPS listener (SNI).
	if httpsListener != "" {
		if _, err := h.aws.ELBV2.AddListenerCertificates(ctx, &elbv2.AddListenerCertificatesInput{
			ListenerArn:  aws.String(httpsListener),
			Certificates: []elbv2types.Certificate{{CertificateArn: aws.String(certARN)}},
		}); err != nil {
			return fmt.Errorf("add listener cert: %w", err)
		}
		if err := h.ensureHostRule(ctx, httpsListener, domainName, backendTG); err != nil {
			return err
		}
	}
	// Host rule on HTTP too so plain-HTTP requests reach the app (backend
	// handles the http→https redirect).
	if httpListener != "" {
		if err := h.ensureHostRule(ctx, httpListener, domainName, backendTG); err != nil {
			return err
		}
	}
	return nil
}

// ensureHostRule creates a host-header rule (if absent) forwarding domainName to
// targetGroup on the given listener, at a deterministic priority.
func (h *DomainHandler) ensureHostRule(ctx context.Context, listenerARN, domainName, targetGroup string) error {
	rules, err := h.aws.ELBV2.DescribeRules(ctx, &elbv2.DescribeRulesInput{
		ListenerArn: aws.String(listenerARN),
	})
	if err != nil {
		return err
	}
	for _, rule := range rules.Rules {
		for _, cond := range rule.Conditions {
			if cond.HostHeaderConfig != nil {
				for _, v := range cond.HostHeaderConfig.Values {
					if strings.EqualFold(v, domainName) {
						return nil // rule already exists
					}
				}
			}
		}
	}

	// Deterministic priority from the domain name, retrying on collision.
	base := priorityFor(domainName)
	for i := int32(0); i < 50; i++ {
		prio := base + i
		if prio > 48000 {
			prio = 1000 + (prio % 40000)
		}
		_, err = h.aws.ELBV2.CreateRule(ctx, &elbv2.CreateRuleInput{
			ListenerArn: aws.String(listenerARN),
			Priority:    aws.Int32(prio),
			Conditions: []elbv2types.RuleCondition{{
				Field:            aws.String("host-header"),
				HostHeaderConfig: &elbv2types.HostHeaderConditionConfig{Values: []string{domainName}},
			}},
			Actions: []elbv2types.Action{{
				Type:           elbv2types.ActionTypeEnumForward,
				TargetGroupArn: aws.String(targetGroup),
			}},
		})
		if err == nil {
			return nil
		}
		if !strings.Contains(err.Error(), "PriorityInUse") {
			return fmt.Errorf("create rule: %w", err)
		}
	}
	return fmt.Errorf("no free ALB rule priority for %s", domainName)
}

func (h *DomainHandler) findLoadBalancerARN(ctx context.Context) (string, error) {
	out, err := h.aws.ELBV2.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{})
	if err != nil {
		return "", err
	}
	for _, lb := range out.LoadBalancers {
		if strings.EqualFold(aws.ToString(lb.DNSName), h.albDNSName) {
			return aws.ToString(lb.LoadBalancerArn), nil
		}
	}
	return "", fmt.Errorf("load balancer %q not found", h.albDNSName)
}

func (h *DomainHandler) findTargetGroupARN(ctx context.Context, name string) (string, error) {
	out, err := h.aws.ELBV2.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{
		Names: []string{name},
	})
	if err != nil {
		return "", err
	}
	if len(out.TargetGroups) == 0 {
		return "", fmt.Errorf("target group %q not found", name)
	}
	return aws.ToString(out.TargetGroups[0].TargetGroupArn), nil
}

func priorityFor(s string) int32 {
	hsh := fnv.New32a()
	_, _ = hsh.Write([]byte(s))
	// Keep in a safe custom-rule band 1000..41000.
	return int32(1000 + (hsh.Sum32() % 40000))
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
