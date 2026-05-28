package awsclient

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	elasticloadbalancingv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/scheduler"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

// Clients holds initialised AWS service clients.
type Clients struct {
	ECR       *ecr.Client
	ECS       *ecs.Client
	ELBV2     *elasticloadbalancingv2.Client
	RDS       *rds.Client
	Route53   *route53.Client
	Bedrock   *bedrockruntime.Client
	S3        *s3.Client
	SES       *sesv2.Client
	Lambda    *lambda.Client
	CE        *costexplorer.Client
	Scheduler *scheduler.Client
	SQS       *sqs.Client
	Region    string
	Account   string
}

// New creates AWS service clients using static credentials.
// If accessKeyID or secretKey are empty the default credential chain is used.
func New(ctx context.Context, region, accessKeyID, secretKey, account string) (*Clients, error) {
	if region == "" {
		region = "us-east-1"
	}

	var opts []func(*config.LoadOptions) error
	opts = append(opts, config.WithRegion(region))

	if accessKeyID != "" && secretKey != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKeyID, secretKey, ""),
		))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading aws config: %w", err)
	}

	_ = aws.ToString(aws.String(region)) // satisfy import

	// Cost Explorer is global — always us-east-1
	ceCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return nil, fmt.Errorf("loading aws config for ce: %w", err)
	}
	if accessKeyID != "" && secretKey != "" {
		ceCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion("us-east-1"),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretKey, "")),
		)
		if err != nil {
			return nil, fmt.Errorf("loading aws config for ce (static): %w", err)
		}
	}

	return &Clients{
		ECR:       ecr.NewFromConfig(cfg),
		ECS:       ecs.NewFromConfig(cfg),
		ELBV2:     elasticloadbalancingv2.NewFromConfig(cfg),
		RDS:       rds.NewFromConfig(cfg),
		Route53:   route53.NewFromConfig(cfg),
		Bedrock:   bedrockruntime.NewFromConfig(cfg),
		S3:        s3.NewFromConfig(cfg),
		SES:       sesv2.NewFromConfig(cfg),
		Lambda:    lambda.NewFromConfig(cfg),
		CE:        costexplorer.NewFromConfig(ceCfg),
		Scheduler: scheduler.NewFromConfig(cfg),
		SQS:       sqs.NewFromConfig(cfg),
		Region:    region,
		Account:   account,
	}, nil
}
