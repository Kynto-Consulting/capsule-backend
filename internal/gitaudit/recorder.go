package gitaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

// maxValuesBytes bounds old_values + new_values + metadata of one entry.
const maxValuesBytes = 32 * 1024

// Input is what a package hands to Record.
type Input struct {
	OrgID        uuid.UUID // required
	ProjectID    uuid.UUID // optional
	UserID       uuid.UUID // optional (uuid.Nil: no user)
	ActorLabel   string    // used when UserID is nil, e.g. "system"
	Action       string
	ResourceType string
	ResourceID   uuid.UUID // optional
	IP           string    // with or without port; invalid values are dropped
	UserAgent    string
	Old, New     map[string]any
	Meta         map[string]any
}

// Recorder validates and appends audit entries. Values must never carry secrets: keys that look
// like credentials are rejected (gitevents.CheckNoSecrets) instead of being stored.
type Recorder struct {
	w   Writer
	now func() time.Time
}

// NewRecorder builds a recorder over w.
func NewRecorder(w Writer) *Recorder { return &Recorder{w: w, now: time.Now} }

// ErrInvalidEntry is wrapped by every validation error of Record.
var ErrInvalidEntry = errors.New("gitaudit: invalid audit entry")

// NormalizeIP returns the bare address of s ("1.2.3.4:5678" and "[::1]:80" lose the port, a zone
// is dropped) or "" when s is not an IP address. audit_logs.ip_address is inet: a port makes the
// insert fail, so it must be removed before writing.
func NormalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().WithZone("").Unmap().String()
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return a.WithZone("").Unmap().String()
	}
	return ""
}

// Record appends one entry.
func (r *Recorder) Record(ctx context.Context, in Input) error {
	if in.OrgID == uuid.Nil {
		return fmt.Errorf("%w: org id is required", ErrInvalidEntry)
	}
	if !ValidAction(in.Action) {
		return fmt.Errorf("%w: action %q", ErrInvalidEntry, in.Action)
	}
	if !ValidResourceType(in.ResourceType) {
		return fmt.Errorf("%w: resource type %q", ErrInvalidEntry, in.ResourceType)
	}
	size := 0
	for _, m := range []map[string]any{in.Old, in.New, in.Meta} {
		if m == nil {
			continue
		}
		if err := gitevents.CheckNoSecrets(m); err != nil {
			return fmt.Errorf("%w: values must not carry secrets", ErrInvalidEntry)
		}
		b, err := json.Marshal(m)
		if err != nil {
			return fmt.Errorf("%w: values are not JSON", ErrInvalidEntry)
		}
		size += len(b)
	}
	if size > maxValuesBytes {
		return fmt.Errorf("%w: values exceed %d bytes", ErrInvalidEntry, maxValuesBytes)
	}
	e := Entry{
		ID: uuid.New(), OrgID: in.OrgID, Action: in.Action, ResourceType: in.ResourceType,
		ActorLabel: oneLine(in.ActorLabel, 100), IP: NormalizeIP(in.IP), UserAgent: oneLine(in.UserAgent, 500),
		OldValues: in.Old, NewValues: in.New, Metadata: in.Meta, CreatedAt: r.now().UTC(),
	}
	if in.ProjectID != uuid.Nil {
		p := in.ProjectID
		e.ProjectID = &p
	}
	if in.UserID != uuid.Nil {
		u := in.UserID
		e.UserID = &u
	}
	if in.ResourceID != uuid.Nil {
		x := in.ResourceID
		e.ResourceID = &x
	}
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
	return r.w.Append(ctx, e)
}

// FromAuthz adapts the authz.AuditEntry written by project_members, org and the authz package
// onto Record, stripping the port of the IP first (authz rejects an IP with a port).
func (r *Recorder) FromAuthz(ctx context.Context, e authz.AuditEntry) error {
	return r.Record(ctx, Input{OrgID: e.OrgID, UserID: e.UserID, Action: e.Action, ResourceType: e.ResourceType,
		ResourceID: e.ResourceID, IP: e.IP, Old: e.OldValues, New: e.NewValues})
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)), " ")
	if len(s) > max {
		s = s[:max]
	}
	return s
}

var (
	sharedMu sync.RWMutex
	shared   *Recorder
)

// SetShared publishes the process-wide recorder (called by the wiring).
func SetShared(r *Recorder) {
	sharedMu.Lock()
	shared = r
	sharedMu.Unlock()
}

// Shared returns the recorder published by the wiring, or nil before that.
func Shared() *Recorder {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return shared
}
