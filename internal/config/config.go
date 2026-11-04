package config

import (
	"fmt"
	"os"
	"strings"
	"strconv"
	"time"
)

type Config struct {
	Env       string
	Port      int
	LogLevel  string
	SecretKey string

	DatabaseURL string
	RedisURL    string

	JWTAccessTTL  time.Duration
	JWTRefreshTTL time.Duration

	RateLimitRPS   int
	RateLimitBurst int

	CORSAllowedOrigins []string

	// AWS
	AWSRegion      string
	AWSAccountID   string
	ECRRegistry    string
	ArtifactsBucket string

	// Infrastructure
	ALBDNSName         string
	DBSubnetGroup      string
	RDSSecurityGroupID string
	AppSecurityGroupID string // security group of the app host; per-database network access rules are applied to it (APP_SECURITY_GROUP_ID)
	PublicHost         string
	DBHost             string // host shown in database connection strings (must resolve to the EC2 host, not the ALB)
	PortRange          string // host port range for extra project TCP ports (CAPSULE_PORT_RANGE, default 41000-41999)
	TCPHost            string // host shown for extra project TCP ports (CAPSULE_TCP_HOST, default = DBHost)

	// Platform domain (e.g. apps.example.com) — used to build default URLs shown to users
	AppsDomain   string
	StaticBucket string

	// ECS Fargate deploy targets
	ECSCluster          string // ARN or name of the ECS cluster
	ECSSubnets          string // comma-separated subnet IDs for Fargate tasks
	ECSSecurityGroup    string // SG ID attached to Fargate tasks
	ECSExecutionRoleARN string // IAM role ARN for ECS task execution (ECR pull + CloudWatch logs)
	ALBListenerARN      string // ARN of the ALB HTTPS/HTTP listener for dynamic rules
	VpcID               string // VPC ID used when creating ALB target groups

	// Ingress without ALB (see internal/ingress). CAPSULE_INGRESS=alb|caddy (default: caddy when ALB_LISTENER_ARN is empty).
	Ingress     string // CAPSULE_INGRESS
	IngressHost string // CAPSULE_INGRESS_HOST: name customers CNAME to (e.g. ingress.apps.example.com)
	IngressIPv4 string // CAPSULE_INGRESS_IPV4: server public IPv4 for A records
	IngressIPv6 string // CAPSULE_INGRESS_IPV6: server public IPv6 for AAAA records

	// Observability
	SentryDSN string

	// OIDC provider (Capsule as login system for Forgejo etc.)
	OIDCIssuer             string // CAPSULE_OIDC_ISSUER
	FrontendURL            string // CAPSULE_FRONTEND_URL (consent screen host)
	OIDCSigningKey         string // CAPSULE_OIDC_SIGNING_KEY (PEM, optional)
	OIDCPreviousSigningKey string // CAPSULE_OIDC_PREVIOUS_SIGNING_KEY (PEM, optional, rotation)
}

func Load() (*Config, error) {
	env := getEnv("CAPSULE_ENV", "development")

	port, err := strconv.Atoi(getEnv("CAPSULE_PORT", "8080"))
	if err != nil {
		return nil, fmt.Errorf("invalid CAPSULE_PORT: %w", err)
	}

	rps, err := strconv.Atoi(getEnv("RATE_LIMIT_RPS", "100"))
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_RPS: %w", err)
	}

	burst, err := strconv.Atoi(getEnv("RATE_LIMIT_BURST", "200"))
	if err != nil {
		return nil, fmt.Errorf("invalid RATE_LIMIT_BURST: %w", err)
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	secretKey := os.Getenv("CAPSULE_SECRET_KEY")
	if secretKey == "" {
		return nil, fmt.Errorf("CAPSULE_SECRET_KEY is required")
	}

	accountID := os.Getenv("AWS_ACCOUNT_ID")

	return &Config{
		Env:                env,
		Port:               port,
		LogLevel:           getEnv("CAPSULE_LOG_LEVEL", "info"),
		SecretKey:          secretKey,
		DatabaseURL:        dbURL,
		RedisURL:           getEnv("REDIS_URL", "redis://localhost:6379/0"),
		JWTAccessTTL:       15 * time.Minute,
		JWTRefreshTTL:      7 * 24 * time.Hour,
		RateLimitRPS:       rps,
		RateLimitBurst:     burst,
		CORSAllowedOrigins: splitEnvList("CORS_ALLOWED_ORIGINS", defaultCORSAllowedOrigins(env)),

		AWSRegion:       getEnv("AWS_DEFAULT_REGION", "us-east-1"),
		AWSAccountID:    accountID,
		ECRRegistry:     os.Getenv("ECR_REGISTRY"),
		ArtifactsBucket: getEnv("ARTIFACTS_BUCKET", artifactsBucketDefault(accountID)),

		ALBDNSName:         os.Getenv("ALB_DNS_NAME"),
		DBSubnetGroup:      getEnv("DB_SUBNET_GROUP", "capsule"),
		RDSSecurityGroupID: os.Getenv("RDS_SECURITY_GROUP_ID"),
		AppSecurityGroupID: os.Getenv("APP_SECURITY_GROUP_ID"),
		PublicHost:         os.Getenv("CAPSULE_PUBLIC_HOST"),
		DBHost:             getEnv("CAPSULE_DB_HOST", os.Getenv("CAPSULE_PUBLIC_HOST")),
		PortRange:          getEnv("CAPSULE_PORT_RANGE", "41000-41999"),
		TCPHost:            getEnv("CAPSULE_TCP_HOST", getEnv("CAPSULE_DB_HOST", os.Getenv("CAPSULE_PUBLIC_HOST"))),

		AppsDomain:   os.Getenv("CAPSULE_APPS_DOMAIN"),
		StaticBucket: getEnv("CAPSULE_STATIC_BUCKET", staticBucketDefault(accountID)),

		ECSCluster:          os.Getenv("ECS_CLUSTER"),
		ECSSubnets:          os.Getenv("ECS_SUBNETS"),
		ECSSecurityGroup:    os.Getenv("ECS_SECURITY_GROUP"),
		ECSExecutionRoleARN: os.Getenv("ECS_EXECUTION_ROLE_ARN"),
		ALBListenerARN:      os.Getenv("ALB_LISTENER_ARN"),
		VpcID:               os.Getenv("VPC_ID"),

		Ingress:     os.Getenv("CAPSULE_INGRESS"),
		IngressHost: os.Getenv("CAPSULE_INGRESS_HOST"),
		IngressIPv4: os.Getenv("CAPSULE_INGRESS_IPV4"),
		IngressIPv6: os.Getenv("CAPSULE_INGRESS_IPV6"),

		SentryDSN: os.Getenv("SENTRY_DSN"),

		OIDCIssuer:             strings.TrimRight(getEnv("CAPSULE_OIDC_ISSUER", "https://api.tumi-ai.com"), "/"),
		FrontendURL:            strings.TrimRight(getEnv("CAPSULE_FRONTEND_URL", "https://app.tumi-ai.com"), "/"),
		OIDCSigningKey:         os.Getenv("CAPSULE_OIDC_SIGNING_KEY"),
		OIDCPreviousSigningKey: os.Getenv("CAPSULE_OIDC_PREVIOUS_SIGNING_KEY"),
	}, nil
}

func artifactsBucketDefault(accountID string) string {
	if accountID != "" {
		return "capsule-artifacts-" + accountID
	}
	return "capsule-artifacts"
}

func staticBucketDefault(accountID string) string {
	if accountID != "" {
		return "capsule-static-" + accountID
	}
	return "capsule-static"
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func defaultCORSAllowedOrigins(env string) []string {
	if env == "production" {
		if origins := os.Getenv("CORS_ALLOWED_ORIGINS"); origins != "" {
			return strings.Split(origins, ",")
		}
		return []string{}
	}
	return []string{"http://localhost:3000", "http://127.0.0.1:3000"}
}

func splitEnvList(key string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return append([]string(nil), fallback...)
	}

	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	if len(values) == 0 {
		return append([]string(nil), fallback...)
	}
	return values
}
