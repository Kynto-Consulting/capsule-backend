// Package gitaudit is Git Capsule package C2 (audit): the append-only audit trail of an
// organization (table audit_logs) and its read side.
//
// Immutability: nothing here updates or deletes an audit row. Writer can only Append, Reader can
// only read, and no HTTP route other than GET exists. The single exception is retention
// (Retention.Run), which removes rows older than MinRetentionDays (400) and is never reachable
// from the API.
package gitaudit

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Entry is one audit_logs row as the API shows it.
type Entry struct {
	ID           uuid.UUID
	OrgID        uuid.UUID
	ProjectID    *uuid.UUID
	UserID       *uuid.UUID
	ActorName    string
	ActorEmail   string
	ActorLabel   string // who acted when there is no user ("system")
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	IP           string
	UserAgent    string
	OldValues    map[string]any
	NewValues    map[string]any
	Metadata     map[string]any
	CreatedAt    time.Time
}

// Filter narrows a listing. Zero fields do not filter.
type Filter struct {
	// Action is an exact action ("git.protection.change") or a prefix ending in "*" ("git.*").
	Action string
	// Actor is a user id, an email or an actor label ("system").
	Actor     string
	ProjectID *uuid.UUID
	Since     *time.Time
	Until     *time.Time
}

// Cursor is the decoded next_cursor: the (created_at, id) of the last row of the previous page.
// Rows are ordered by (created_at DESC, id DESC) and the next page is strictly after that pair,
// so the pages are stable while new rows are appended (new rows are newer and never shift older ones).
type Cursor struct {
	At time.Time
	ID uuid.UUID
}

// ErrInvalidCursor is returned for a malformed cursor.
var ErrInvalidCursor = errors.New("invalid cursor")

// Encode renders the cursor as an opaque string.
func (c Cursor) Encode() string {
	return base64.RawURLEncoding.EncodeToString([]byte("a1|" + strconv.FormatInt(c.At.UnixMicro(), 10) + "|" + c.ID.String()))
}

// ParseCursor decodes a cursor produced by Encode ("" = nil, nil).
func ParseCursor(s string) (*Cursor, error) {
	if s == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, ErrInvalidCursor
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 || parts[0] != "a1" {
		return nil, ErrInvalidCursor
	}
	us, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, ErrInvalidCursor
	}
	id, err := uuid.Parse(parts[2])
	if err != nil {
		return nil, ErrInvalidCursor
	}
	return &Cursor{At: time.UnixMicro(us).UTC(), ID: id}, nil
}

// Writer is the whole write surface: appending. There is deliberately no update or delete.
type Writer interface {
	Append(ctx context.Context, e Entry) error
}

// Reader is the read surface.
type Reader interface {
	// List returns up to limit entries of the organization, newest first, strictly after the
	// cursor (nil = from the start).
	List(ctx context.Context, orgID uuid.UUID, f Filter, after *Cursor, limit int) ([]Entry, error)
	// ProjectID resolves a project id or slug of the organization. ok=false when it does not exist.
	ProjectID(ctx context.Context, orgID uuid.UUID, ref string) (id uuid.UUID, ok bool, err error)
}

// Retainer removes rows older than cutoff. Only Retention uses it.
type Retainer interface {
	PurgeBefore(ctx context.Context, cutoff time.Time) (int64, error)
}
