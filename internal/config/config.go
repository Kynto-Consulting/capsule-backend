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
	PublicHost         string

	// Platform domain (e.g. apps.example.com) — used to build default URLs shown to users
	AppsDomain   string
	StaticBucket string

	// Observability
	SentryDSN string
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
		PublicHost:         os.Getenv("CAPSULE_PUBLIC_HOST"),

		AppsDomain:   os.Getenv("CAPSULE_APPS_DOMAIN"),
		StaticBucket: getEnv("CAPSULE_STATIC_BUCKET", staticBucketDefault(accountID)),

		SentryDSN: os.Getenv("SENTRY_DSN"),
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
