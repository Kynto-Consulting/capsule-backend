package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/pkg/awsclient"
)

// S3Uploader uploads git snapshots to the artifacts bucket, the same place
// (and key layout) as CLI uploads.
type S3Uploader struct {
	AWS    *awsclient.Clients
	Bucket string
}

func (u S3Uploader) Upload(ctx context.Context, key, path string) error {
	if u.AWS == nil || u.AWS.S3 == nil {
		return errors.New("AWS clients not configured")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = u.AWS.S3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(u.Bucket),
		Key:    aws.String(key),
		Body:   f,
	})
	return err
}

// AppRemover removes the running app of a project from this host (docker) and,
// when configured, from ECS Fargate + the ALB. Every step is best effort; the
// returned error summarizes failures.
type AppRemover struct {
	AWS     *awsclient.Clients
	Fargate FargateConfig
	Logger  *slog.Logger
}

func (a AppRemover) Remove(ctx context.Context, projectID uuid.UUID) error {
	if a.Logger == nil {
		a.Logger = slog.Default()
	}
	short := strings.ReplaceAll(projectID.String(), "-", "")[:12]
	name := "capsule-app-" + short
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var errs []string

	// Local docker (same names the deploy worker uses).
	for _, args := range [][]string{
		{"rm", "-f", name},
		{"rmi", "-f", name},
		{"volume", "rm", "-f", "capsule-data-" + projectID.String()},
	} {
		if _, err := exec.LookPath("docker"); err != nil {
			break
		}
		if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
			msg := strings.TrimSpace(string(out))
			if !strings.Contains(strings.ToLower(msg), "no such") {
				errs = append(errs, fmt.Sprintf("docker %s: %s", args[0], msg))
			}
		}
	}

	// ECS Fargate + ALB.
	if a.AWS != nil && a.Fargate.IsConfigured() {
		if a.AWS.ECS != nil {
			if _, err := a.AWS.ECS.DeleteService(ctx, &ecs.DeleteServiceInput{
				Cluster: aws.String(a.Fargate.Cluster), Service: aws.String(name), Force: aws.Bool(true),
			}); err != nil && !strings.Contains(err.Error(), "ServiceNotFound") && !strings.Contains(err.Error(), "ServiceNotActive") {
				errs = append(errs, "ecs delete service: "+err.Error())
			}
		}
		if a.AWS.ELBV2 != nil {
			host := short + "." + a.Fargate.AppsDomain
			if rules, err := a.AWS.ELBV2.DescribeRules(ctx, &elbv2.DescribeRulesInput{ListenerArn: aws.String(a.Fargate.ALBListenerARN)}); err == nil {
			rules:
				for _, rule := range rules.Rules {
					for _, c := range rule.Conditions {
						if aws.ToString(c.Field) != "host-header" {
							continue
						}
						for _, v := range c.Values {
							if v == host {
								if _, err := a.AWS.ELBV2.DeleteRule(ctx, &elbv2.DeleteRuleInput{RuleArn: rule.RuleArn}); err != nil {
									errs = append(errs, "alb delete rule: "+err.Error())
								}
								continue rules
							}
						}
					}
				}
			}
			// The target group stays attached while the service drains; tolerate failure.
			if tg, err := a.AWS.ELBV2.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{Names: []string{name}}); err == nil && len(tg.TargetGroups) > 0 {
				if _, err := a.AWS.ELBV2.DeleteTargetGroup(ctx, &elbv2.DeleteTargetGroupInput{TargetGroupArn: tg.TargetGroups[0].TargetGroupArn}); err != nil {
					a.Logger.Info("preview cleanup: target group still in use; will remain until the service drains", "name", name)
				}
			}
		}
		if a.AWS.ECR != nil {
			_, err := a.AWS.ECR.DeleteRepository(ctx, &ecr.DeleteRepositoryInput{
				RepositoryName: aws.String("capsule-apps/" + short), Force: true,
			})
			if err != nil && !strings.Contains(err.Error(), "RepositoryNotFound") {
				errs = append(errs, "ecr delete repository: "+err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
