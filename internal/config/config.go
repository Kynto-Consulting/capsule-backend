package config

import (
	"fmt"
	"os"
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
}

func Load() (*Config, error) {
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

	return &Config{
		Env:                getEnv("CAPSULE_ENV", "development"),
		Port:               port,
		LogLevel:           getEnv("CAPSULE_LOG_LEVEL", "info"),
		SecretKey:          secretKey,
		DatabaseURL:        dbURL,
		RedisURL:           getEnv("REDIS_URL", "redis://localhost:6379/0"),
		JWTAccessTTL:       15 * time.Minute,
		JWTRefreshTTL:      7 * 24 * time.Hour,
		RateLimitRPS:       rps,
		RateLimitBurst:     burst,
		CORSAllowedOrigins: []string{"http://localhost:3000"},

		AWSRegion:          getEnv("AWS_DEFAULT_REGION", "us-east-1"),
		AWSAccountID:       os.Getenv("AWS_ACCOUNT_ID"),
		ECRRegistry:        os.Getenv("ECR_REGISTRY"),
		ArtifactsBucket:    getEnv("ARTIFACTS_BUCKET", "capsule-artifacts-348973061281"),

		ALBDNSName:         os.Getenv("ALB_DNS_NAME"),
		DBSubnetGroup:      getEnv("DB_SUBNET_GROUP", "capsule"),
		RDSSecurityGroupID: os.Getenv("RDS_SECURITY_GROUP_ID"),
	}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
