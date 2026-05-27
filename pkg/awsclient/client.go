package awsclient

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

// Clients holds initialised AWS service clients.
type Clients struct {
	ECR     *ecr.Client
	RDS     *rds.Client
	Route53 *route53.Client
	Bedrock *bedrockruntime.Client
	S3      *s3.Client
	SES     *sesv2.Client
	Lambda  *lambda.Client
	Region  string
	Account string
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

	return &Clients{
		ECR:     ecr.NewFromConfig(cfg),
		RDS:     rds.NewFromConfig(cfg),
		Route53: route53.NewFromConfig(cfg),
		Bedrock: bedrockruntime.NewFromConfig(cfg),
		S3:      s3.NewFromConfig(cfg),
		SES:     sesv2.NewFromConfig(cfg),
		Lambda:  lambda.NewFromConfig(cfg),
		Region:  region,
		Account: account,
	}, nil
}
