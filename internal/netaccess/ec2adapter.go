package netaccess

import (
	"context"
	"errors"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
)

// EC2Client is the subset of *ec2.Client used by the adapter.
type EC2Client interface {
	DescribeSecurityGroupRules(ctx context.Context, in *ec2.DescribeSecurityGroupRulesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupRulesOutput, error)
	AuthorizeSecurityGroupIngress(ctx context.Context, in *ec2.AuthorizeSecurityGroupIngressInput, optFns ...func(*ec2.Options)) (*ec2.AuthorizeSecurityGroupIngressOutput, error)
	RevokeSecurityGroupIngress(ctx context.Context, in *ec2.RevokeSecurityGroupIngressInput, optFns ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error)
}

// AWSAdapter implements EC2API on top of the AWS SDK.
type AWSAdapter struct{ Client EC2Client }

func (a AWSAdapter) ListIngressRules(ctx context.Context, sgID string) ([]Rule, error) {
	var out []Rule
	var token *string
	for {
		resp, err := a.Client.DescribeSecurityGroupRules(ctx, &ec2.DescribeSecurityGroupRulesInput{
			Filters:   []ec2types.Filter{{Name: aws.String("group-id"), Values: []string{sgID}}},
			NextToken: token,
		})
		if err != nil {
			return nil, err
		}
		for _, r := range resp.SecurityGroupRules {
			if aws.ToBool(r.IsEgress) || r.CidrIpv4 == nil {
				continue
			}
			if aws.ToString(r.IpProtocol) != "tcp" || aws.ToInt32(r.FromPort) != aws.ToInt32(r.ToPort) {
				continue
			}
			out = append(out, Rule{
				RuleID:      aws.ToString(r.SecurityGroupRuleId),
				Port:        int(aws.ToInt32(r.FromPort)),
				CIDR:        aws.ToString(r.CidrIpv4),
				Description: aws.ToString(r.Description),
			})
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			return out, nil
		}
		token = resp.NextToken
	}
}

func (a AWSAdapter) AuthorizeIngress(ctx context.Context, sgID string, port int, cidr, description string) error {
	_, err := a.Client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(sgID),
		IpPermissions: []ec2types.IpPermission{{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(int32(port)),
			ToPort:     aws.Int32(int32(port)),
			IpRanges:   []ec2types.IpRange{{CidrIp: aws.String(cidr), Description: aws.String(description)}},
		}},
	})
	return err
}

func (a AWSAdapter) RevokeIngressByID(ctx context.Context, sgID string, ruleIDs []string) error {
	if len(ruleIDs) == 0 {
		return nil
	}
	_, err := a.Client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
		GroupId:              aws.String(sgID),
		SecurityGroupRuleIds: ruleIDs,
	})
	if err != nil && apiCode(err) == "InvalidSecurityGroupRuleId.NotFound" {
		return nil // already gone
	}
	return err
}

func apiCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}

// IsDuplicate reports an "identical rule already exists" AWS error.
func IsDuplicate(err error) bool { return apiCode(err) == "InvalidPermission.Duplicate" }

// IsLimitExceeded reports an AWS security-group rule quota error.
func IsLimitExceeded(err error) bool {
	return strings.Contains(apiCode(err), "LimitExceeded")
}
