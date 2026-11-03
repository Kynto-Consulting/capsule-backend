package security

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is read from the package's own environment (rule 0.2: not in config.go).
//
//	SECURITY_FINGERPRINT_KEY       HMAC key of secret fingerprints (default: the platform secret key)
//	SECURITY_WORKER_SECONDS        poll period of the upload worker (default 5)
//	SECURITY_SWEEP_MINUTES         period of expiry/notice/check sweeps (default 5)
//	SECURITY_CHECK_TIMEOUT_MINUTES capsule/security fails closed after this wait for a required tool (default 30)
//	SECURITY_UPLOADS_PER_MINUTE    SARIF uploads per project per minute (default 30)
//	SECURITY_RENOVATE_BOT_LOGIN    Forgejo login of the Renovate service account (default renovate-bot)
//	SECURITY_RENOVATE_PRESET       default preset (default local>platform/renovate-config)
//	SECURITY_RENOVATE_PROJECT_ID   Capsule project that hosts the renovate-bot container ("" = runs disabled)
//	SECURITY_RENOVATE_COMMAND      command inside that container (default renovate)
type Config struct {
	FingerprintKey   string
	WorkerEvery      time.Duration
	SweepEvery       time.Duration
	CheckTimeout     time.Duration
	UploadsPerMinute int
	RenovateBotLogin string
	RenovatePreset   string
	RenovateProject  string
	RenovateCommand  string
}

// DefaultConfig is what ConfigFromEnv returns with an empty environment.
func DefaultConfig() Config {
	return Config{
		WorkerEvery:      5 * time.Second,
		SweepEvery:       5 * time.Minute,
		CheckTimeout:     30 * time.Minute,
		UploadsPerMinute: 30,
		RenovateBotLogin: "renovate-bot",
		RenovatePreset:   "local>platform/renovate-config",
		RenovateCommand:  "renovate",
	}
}

// ConfigFromEnv reads the SECURITY_* variables.
func ConfigFromEnv() Config {
	c := DefaultConfig()
	c.FingerprintKey = strings.TrimSpace(os.Getenv("SECURITY_FINGERPRINT_KEY"))
	if n := envInt("SECURITY_WORKER_SECONDS"); n > 0 {
		c.WorkerEvery = time.Duration(n) * time.Second
	}
	if n := envInt("SECURITY_SWEEP_MINUTES"); n > 0 {
		c.SweepEvery = time.Duration(n) * time.Minute
	}
	if n := envInt("SECURITY_CHECK_TIMEOUT_MINUTES"); n > 0 {
		c.CheckTimeout = time.Duration(n) * time.Minute
	}
	if n := envInt("SECURITY_UPLOADS_PER_MINUTE"); n > 0 {
		c.UploadsPerMinute = n
	}
	if v := strings.TrimSpace(os.Getenv("SECURITY_RENOVATE_BOT_LOGIN")); v != "" {
		c.RenovateBotLogin = v
	}
	if v := strings.TrimSpace(os.Getenv("SECURITY_RENOVATE_PRESET")); v != "" {
		c.RenovatePreset = v
	}
	c.RenovateProject = strings.TrimSpace(os.Getenv("SECURITY_RENOVATE_PROJECT_ID"))
	if v := strings.TrimSpace(os.Getenv("SECURITY_RENOVATE_COMMAND")); v != "" {
		c.RenovateCommand = v
	}
	return c
}

func envInt(name string) int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil {
		return 0
	}
	return n
}
