package connaudit

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Mode is the per-project policy.
type Mode string

const (
	ModeWarn   Mode = "warn"   // default: report only
	ModeStrict Mode = "strict" // a critical (unsuppressed) finding fails the deployment before the build
	ModeOff    Mode = "off"    // no analysis
)

// ParseMode validates a mode; "" is the default (warn).
func ParseMode(s string) (Mode, bool) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case "", ModeWarn:
		return ModeWarn, true
	case ModeStrict:
		return ModeStrict, true
	case ModeOff:
		return ModeOff, true
	}
	return ModeWarn, false
}

// BlockedCode is the machine code of a deployment stopped by the strict policy.
const BlockedCode = "CONNECTION_POLICY_BLOCKED"

// Suppression silences one finding id of a project, with a mandatory reason and
// an optional expiry.
type Suppression struct {
	FindingID string     `json:"finding_id"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedBy string     `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// Active reports whether the suppression still applies at now.
func (s Suppression) Active(now time.Time) bool {
	return s.ExpiresAt == nil || now.Before(*s.ExpiresAt)
}

// Validate checks a suppression request.
func (s Suppression) Validate(now time.Time) string {
	id := strings.TrimSpace(s.FindingID)
	if len(id) < 8 || len(id) > 64 || strings.Trim(id, "0123456789abcdef") != "" {
		return "finding_id must be a finding id (lowercase hex)"
	}
	why := strings.TrimSpace(s.Reason)
	if utf8.RuneCountInString(why) < 8 {
		return "reason is required (at least 8 characters): say why this connection is acceptable"
	}
	if utf8.RuneCountInString(why) > 500 {
		return "reason is too long (max 500 characters)"
	}
	if s.ExpiresAt != nil && !s.ExpiresAt.After(now) {
		return "expires_at must be in the future"
	}
	return ""
}

// Apply returns a copy of findings with Suppressed set from the active suppressions.
func Apply(findings []Finding, sups []Suppression, now time.Time) []Finding {
	active := map[string]bool{}
	for _, s := range sups {
		if s.Active(now) {
			active[s.FindingID] = true
		}
	}
	out := make([]Finding, len(findings))
	for i, f := range findings {
		f.Suppressed = active[f.ID]
		out[i] = f
	}
	return out
}

// Blocking returns the findings that stop a deployment under mode: only an
// unsuppressed critical one under strict.
func Blocking(findings []Finding, mode Mode) []Finding {
	if mode != ModeStrict {
		return nil
	}
	var out []Finding
	for _, f := range findings {
		if f.Severity == SevCritical && !f.Suppressed {
			out = append(out, f)
		}
	}
	return out
}

// Counts summarises findings (suppressed ones are listed apart).
type Counts struct {
	Critical, Warning, Info, Suppressed int
}

func Count(findings []Finding) Counts {
	var c Counts
	for _, f := range findings {
		if f.Suppressed {
			c.Suppressed++
			continue
		}
		switch f.Severity {
		case SevCritical:
			c.Critical++
		case SevWarning:
			c.Warning++
		default:
			c.Info++
		}
	}
	return c
}

// Store persists the audit data. Implemented by repository.ConnAuditRepository.
type Store interface {
	Mode(ctx context.Context, projectID uuid.UUID) (Mode, error)
	SetMode(ctx context.Context, projectID uuid.UUID, m Mode) error
	Suppressions(ctx context.Context, projectID uuid.UUID) ([]Suppression, error)
	PutSuppression(ctx context.Context, projectID uuid.UUID, s Suppression) error
	DeleteSuppression(ctx context.Context, projectID uuid.UUID, findingID string) error
	SaveFindings(ctx context.Context, deploymentID uuid.UUID, f []Finding) error
	FindingsFor(ctx context.Context, deploymentIDs []uuid.UUID) (map[uuid.UUID][]Finding, error)
}
