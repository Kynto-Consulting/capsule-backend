package gitimport

import (
	"os"
	"strconv"
	"time"
)

// Config tunes imports and mirrors. Environment (all optional):
//
//	CAPSULE_GIT_IMPORT_MAX_REPOS      repositories per import request (default 50)
//	CAPSULE_GIT_IMPORT_REPO_MINUTES   time limit of the migration of ONE repository (default 30)
//	CAPSULE_GIT_MIRROR_SYNC_MINUTES   time limit of one manual mirror synchronization (default 10)
type Config struct {
	MaxRepos    int
	RepoTimeout time.Duration
	SyncTimeout time.Duration
	// GitHubAPI is the GitHub REST base URL (default https://api.github.com). Tests point it at an httptest server.
	GitHubAPI string
}

// ConfigFromEnv reads the environment.
func ConfigFromEnv() Config {
	var c Config
	if n, err := strconv.Atoi(os.Getenv("CAPSULE_GIT_IMPORT_MAX_REPOS")); err == nil && n > 0 && n <= 500 {
		c.MaxRepos = n
	}
	if n, err := strconv.Atoi(os.Getenv("CAPSULE_GIT_IMPORT_REPO_MINUTES")); err == nil && n > 0 {
		c.RepoTimeout = time.Duration(n) * time.Minute
	}
	if n, err := strconv.Atoi(os.Getenv("CAPSULE_GIT_MIRROR_SYNC_MINUTES")); err == nil && n > 0 {
		c.SyncTimeout = time.Duration(n) * time.Minute
	}
	return c.withDefaults()
}

func (c Config) withDefaults() Config {
	if c.MaxRepos <= 0 {
		c.MaxRepos = 50
	}
	if c.RepoTimeout <= 0 {
		c.RepoTimeout = 30 * time.Minute
	}
	if c.SyncTimeout <= 0 {
		c.SyncTimeout = 10 * time.Minute
	}
	if c.GitHubAPI == "" {
		c.GitHubAPI = "https://api.github.com"
	}
	return c
}
