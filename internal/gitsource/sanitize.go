package gitsource

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var branchRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$`)

// ValidBranch reports whether name is a safe branch name for git arguments:
// no leading dash (option injection), no path traversal, no ref-syntax tricks.
func ValidBranch(name string) bool {
	if !branchRe.MatchString(name) {
		return false
	}
	if strings.Contains(name, "..") || strings.Contains(name, "//") ||
		strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".") ||
		strings.HasSuffix(name, ".lock") || strings.Contains(name, "/.") ||
		strings.Contains(name, "@{") {
		return false
	}
	return true
}

var slugRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,98}[a-z0-9])?$`)

// ValidSlug reports whether s is a safe project slug.
func ValidSlug(s string) bool { return slugRe.MatchString(s) }

// PreviewSlug builds "<parent>-pr-<n>" (max 100 chars, parent truncated).
func PreviewSlug(parentSlug string, pr int) (string, error) {
	if pr <= 0 || pr > 99999999 {
		return "", errors.New("invalid pull request number")
	}
	suffix := fmt.Sprintf("-pr-%d", pr)
	base := strings.Trim(parentSlug, "-")
	if len(base)+len(suffix) > 100 {
		base = strings.Trim(base[:100-len(suffix)], "-")
	}
	s := base + suffix
	if !ValidSlug(s) {
		return "", errors.New("invalid parent slug")
	}
	return s, nil
}

var shaRe = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

// ValidSHA reports whether s looks like a git object id.
func ValidSHA(s string) bool { return shaRe.MatchString(s) }
