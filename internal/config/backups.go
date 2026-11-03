package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Backups is the platform-level data backup configuration (CAPSULE_BACKUPS_*).
type Backups struct {
	Enabled              bool   // CAPSULE_BACKUPS_ENABLED; when unset: true only if the bucket is set
	Bucket               string // CAPSULE_BACKUPS_BUCKET
	DefaultSchedule      string // CAPSULE_BACKUPS_DEFAULT_SCHEDULE (default daily)
	DefaultOn            bool   // CAPSULE_BACKUPS_DEFAULT_ON (default true)
	DefaultRetentionDays int    // CAPSULE_BACKUPS_DEFAULT_RETENTION_DAYS (default 14)
	BucketRetentionDays  int    // CAPSULE_BACKUPS_BUCKET_RETENTION_DAYS (default 30; = Terraform backup_s3_retention_days)
	HelperImage          string // CAPSULE_BACKUPS_HELPER_IMAGE (needs GNU tar + gzip; sqlite3 optional)
	PlatformDir          string // CAPSULE_BACKUPS_PLATFORM_DIR (host dir with docker-compose*.yml, .env, certs/)
	DockerConfigDir      string // CAPSULE_BACKUPS_DOCKER_CONFIG_DIR (host dir with daemon.json)
	RunTimeout           time.Duration
}

func envBool(name string, def bool) bool {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envInt(name string, def int) int {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// LoadBackups reads the backup settings from the environment.
func LoadBackups() Backups {
	bucket := strings.TrimSpace(os.Getenv("CAPSULE_BACKUPS_BUCKET"))
	return Backups{
		Enabled:              envBool("CAPSULE_BACKUPS_ENABLED", bucket != "") && bucket != "",
		Bucket:               bucket,
		DefaultSchedule:      getEnv("CAPSULE_BACKUPS_DEFAULT_SCHEDULE", "daily"),
		DefaultOn:            envBool("CAPSULE_BACKUPS_DEFAULT_ON", true),
		DefaultRetentionDays: envInt("CAPSULE_BACKUPS_DEFAULT_RETENTION_DAYS", 14),
		BucketRetentionDays:  envInt("CAPSULE_BACKUPS_BUCKET_RETENTION_DAYS", 30),
		HelperImage:          os.Getenv("CAPSULE_BACKUPS_HELPER_IMAGE"),
		PlatformDir:          os.Getenv("CAPSULE_BACKUPS_PLATFORM_DIR"),
		DockerConfigDir:      os.Getenv("CAPSULE_BACKUPS_DOCKER_CONFIG_DIR"),
		RunTimeout:           4 * time.Hour,
	}
}
