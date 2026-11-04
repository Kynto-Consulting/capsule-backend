package access

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AuditEntry is one row of the access audit trail (AuditPage schema).
type AuditEntry struct {
	ID           uuid.UUID      `json:"id"`
	Action       string         `json:"action"`
	Actor        *UserRef       `json:"actor"`
	ActorLabel   string         `json:"actor_label"`
	ResourceType string         `json:"resource_type"`
	ResourceID   *uuid.UUID     `json:"resource_id"`
	ProjectID    *uuid.UUID     `json:"project_id"`
	OldValues    map[string]any `json:"old_values"`
	NewValues    map[string]any `json:"new_values"`
	Metadata     map[string]any `json:"metadata"`
	IPAddress    *string        `json:"ip_address"`
	CreatedAt    time.Time      `json:"created_at"`
}

// AuditPage is a page of audit rows.
type AuditPage struct {
	Data       []AuditEntry `json:"data"`
	NextCursor *string      `json:"next_cursor"`
}

// AuditQuery is the query string of GET .../access-audit.
type AuditQuery struct {
	Action, Actor, Subject, Project, Since, Until, Cursor string
	Limit                                                 int
	CSV                                                   bool
}

// AccessAudit lists the access.* rows of audit_logs of the organization (audit:read; CSV also audit:export).
func (s *Service) AccessAudit(ctx context.Context, actor Actor, org uuid.UUID, qy AuditQuery) (*AuditPage, error) {
	perms := []string{"audit:read"}
	if qy.CSV {
		perms = append(perms, "audit:export")
	}
	if _, err := s.require(ctx, actor, org, orgScope, perms...); err != nil {
		return nil, err
	}
	where := []string{"a.org_id = $1", "a.action LIKE 'access.%'"}
	args := []any{org}
	add := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if a := qy.Action; a != "" {
		if strings.HasSuffix(a, "*") {
			where = append(where, "a.action LIKE "+add(escapeLike(strings.TrimSuffix(a, "*"))+"%"))
		} else {
			where = append(where, "a.action = "+add(a))
		}
	}
	if qy.Actor != "" {
		u, err := uuid.Parse(qy.Actor)
		if err != nil {
			return nil, validationField("actor", "must be a uuid")
		}
		where = append(where, "a.user_id = "+add(u))
	}
	if qy.Subject != "" {
		u, err := uuid.Parse(qy.Subject)
		if err != nil {
			return nil, validationField("subject", "must be a uuid")
		}
		p := add(u.String())
		where = append(where, fmt.Sprintf(`(a.resource_id::text = %[1]s OR a.new_values->>'subject_id' = %[1]s OR a.old_values->>'subject_id' = %[1]s OR a.new_values->>'user_id' = %[1]s OR a.old_values->>'user_id' = %[1]s)`, p))
	}
	if qy.Project != "" {
		u, err := uuid.Parse(qy.Project)
		if err != nil {
			return nil, validationField("project", "must be a uuid")
		}
		if _, _, _, err := s.requireAt(ctx, actor, org, "project", u); err != nil {
			return nil, err
		}
		where = append(where, "a.project_id = "+add(u))
	}
	for _, f := range []struct {
		field, v, op string
	}{{"since", qy.Since, ">="}, {"until", qy.Until, "<="}} {
		if f.v == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, f.v)
		if err != nil {
			return nil, validationField(f.field, "must be an RFC 3339 date-time")
		}
		where = append(where, "a.created_at "+f.op+" "+add(t))
	}
	limit := clampLimit(qy.Limit)
	if at, id, ok := decodeCursor(qy.Cursor); ok {
		t, err1 := time.Parse(time.RFC3339Nano, at)
		u, err2 := uuid.Parse(id)
		if err1 == nil && err2 == nil {
			where = append(where, fmt.Sprintf("(a.created_at, a.id) < (%s, %s)", add(t), add(u)))
		}
	}
	rows, err := s.q().Query(ctx, `
		SELECT a.id, a.action, u.id, u.email, u.name, a.actor_label, a.resource_type, a.resource_id, a.project_id,
		       a.old_values, a.new_values, a.metadata, host(a.ip_address), a.created_at
		  FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id
		 WHERE `+strings.Join(where, " AND ")+` ORDER BY a.created_at DESC, a.id DESC LIMIT `+add(limit+1), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &AuditPage{Data: []AuditEntry{}}
	for rows.Next() {
		var e AuditEntry
		var uid *uuid.UUID
		var email, name *string
		var oldRaw, newRaw, metaRaw []byte
		if err := rows.Scan(&e.ID, &e.Action, &uid, &email, &name, &e.ActorLabel, &e.ResourceType, &e.ResourceID, &e.ProjectID,
			&oldRaw, &newRaw, &metaRaw, &e.IPAddress, &e.CreatedAt); err != nil {
			return nil, err
		}
		if uid != nil {
			e.Actor = &UserRef{ID: *uid, Email: deref(email), Name: deref(name)}
		}
		_ = json.Unmarshal(oldRaw, &e.OldValues)
		_ = json.Unmarshal(newRaw, &e.NewValues)
		e.Metadata = map[string]any{}
		_ = json.Unmarshal(metaRaw, &e.Metadata)
		page.Data = append(page.Data, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(page.Data) > limit {
		page.Data = page.Data[:limit]
		last := page.Data[limit-1]
		c := encodeCursor(last.CreatedAt.UTC().Format(time.RFC3339Nano), last.ID.String())
		page.NextCursor = &c
	}
	return page, nil
}
