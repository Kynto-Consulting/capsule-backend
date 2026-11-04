package access

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/repository"
)

// GroupInput is the body of POST and PATCH of a group.
type GroupInput struct {
	Slug        string  `json:"slug"`
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

// GroupDTO is the Group schema. Assignments is filled only by GET of one group.
type GroupDTO struct {
	ID          uuid.UUID        `json:"id"`
	Slug        string           `json:"slug"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Source      string           `json:"source"`
	Members     int              `json:"members"`
	Assignments *[]AssignmentDTO `json:"assignments,omitempty"`
	Archived    bool             `json:"archived"`
}

// GroupPage is a page of groups.
type GroupPage struct {
	Data       []GroupDTO `json:"data"`
	NextCursor *string    `json:"next_cursor"`
}

// GroupMemberDTO is one membership.
type GroupMemberDTO struct {
	User      UserRef    `json:"user"`
	Source    string     `json:"source"`
	AddedAt   time.Time  `json:"added_at"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// GroupMemberPage is a page of memberships.
type GroupMemberPage struct {
	Data       []GroupMemberDTO `json:"data"`
	NextCursor *string          `json:"next_cursor"`
}

// AddMembersInput is the body of POST .../members.
type AddMembersInput struct {
	UserIDs   []uuid.UUID `json:"user_ids"`
	ExpiresAt *time.Time  `json:"expires_at"`
}

const groupSelect = `g.id, g.slug, g.name, g.description, g.source, g.archived_at IS NOT NULL, (SELECT count(*) FROM group_members gm WHERE gm.group_id = g.id)`

func scanGroupDTO(row interface{ Scan(...any) error }, g *GroupDTO) error {
	return row.Scan(&g.ID, &g.Slug, &g.Name, &g.Description, &g.Source, &g.Archived, &g.Members)
}

func (s *Service) loadGroup(ctx context.Context, q querier, org, id uuid.UUID) (*GroupDTO, error) {
	var g GroupDTO
	err := scanGroupDTO(q.QueryRow(ctx, `SELECT `+groupSelect+` FROM groups g WHERE g.id = $1 AND g.org_id = $2`, id, org), &g)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// ListGroups returns the organization's groups, by slug (group:read).
func (s *Service) ListGroups(ctx context.Context, actor Actor, org uuid.UUID, search, cursor string, limit int, includeArchived bool) (*GroupPage, error) {
	if _, err := s.require(ctx, actor, org, orgScope, "group:read"); err != nil {
		return nil, err
	}
	limit = clampLimit(limit)
	after, _, _ := decodeCursor(cursor)
	like := ""
	if search != "" {
		like = "%" + escapeLike(strings.ToLower(search)) + "%"
	}
	rows, err := s.q().Query(ctx, `
		SELECT `+groupSelect+` FROM groups g
		 WHERE g.org_id = $1 AND ($2 = '' OR g.slug > $2) AND ($3 = '' OR lower(g.slug) LIKE $3 OR lower(g.name) LIKE $3) AND ($4 OR g.archived_at IS NULL)
		 ORDER BY g.slug LIMIT $5`, org, after, like, includeArchived, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &GroupPage{Data: []GroupDTO{}}
	for rows.Next() {
		var g GroupDTO
		if err := scanGroupDTO(rows, &g); err != nil {
			return nil, err
		}
		page.Data = append(page.Data, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(page.Data) > limit {
		page.Data = page.Data[:limit]
		c := encodeCursor(page.Data[limit-1].Slug, "")
		page.NextCursor = &c
	}
	return page, nil
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// GetGroup returns one group with its live assignments (group:read).
func (s *Service) GetGroup(ctx context.Context, actor Actor, org, id uuid.UUID) (*GroupDTO, error) {
	if _, err := s.require(ctx, actor, org, orgScope, "group:read"); err != nil {
		return nil, err
	}
	g, err := s.loadGroup(ctx, s.q(), org, id)
	if err != nil {
		return nil, Normalize(err)
	}
	asg, err := s.listAssignments(ctx, s.q(), org, assignmentFilter{SubjectType: "group", SubjectID: &id}, "", 200)
	if err != nil {
		return nil, err
	}
	list := asg.Data
	g.Assignments = &list
	return g, nil
}

// CreateGroup creates a group (group:manage); at most 500 per organization.
func (s *Service) CreateGroup(ctx context.Context, actor Actor, org uuid.UUID, in GroupInput, idem *Idem) (Reply[*GroupDTO], error) {
	if _, err := s.require(ctx, actor, org, orgScope, "group:manage"); err != nil {
		return Reply[*GroupDTO]{}, err
	}
	fields := map[string]string{}
	if !slugRE.MatchString(in.Slug) {
		fields["slug"] = "lowercase letters, digits and hyphens, 1 to 40 characters"
	}
	name := ""
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
	}
	if name == "" || len(name) > 80 {
		fields["name"] = "required, at most 80 characters"
	}
	desc := ""
	if in.Description != nil {
		desc = *in.Description
	}
	if len(desc) > 500 {
		fields["description"] = "at most 500 characters"
	}
	if len(fields) > 0 {
		return Reply[*GroupDTO]{}, validation(fields)
	}
	return doWrite(ctx, s, org, actor, idem, 201, func(tx pgx.Tx) (*GroupDTO, error) {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM groups WHERE org_id = $1`, org).Scan(&n); err != nil {
			return nil, err
		}
		if n >= repository.MaxGroupsPerOrg {
			return nil, limitErr(fmt.Sprintf("an organization has at most %d groups", repository.MaxGroupsPerOrg))
		}
		var id uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO groups (org_id, slug, name, description, source, created_by) VALUES ($1,$2,$3,$4,'manual',$5) RETURNING id`,
			org, in.Slug, name, desc, actor.UserID).Scan(&id); err != nil {
			if e := mapPg(err); errors.Is(e, repository.ErrAccessConflict) {
				return nil, conflict("DUPLICATE", "a group with that slug already exists", nil)
			} else {
				return nil, e
			}
		}
		if err := s.audit(ctx, tx, org, actor, auditRow{Action: "access.group.created", ResourceType: "group", ResourceID: id,
			New: map[string]any{"slug": in.Slug, "name": name}}); err != nil {
			return nil, err
		}
		return s.loadGroup(ctx, tx, org, id)
	})
}

// UpdateGroup renames a group or changes its description (group:manage). The slug is immutable.
func (s *Service) UpdateGroup(ctx context.Context, actor Actor, org, id uuid.UUID, in GroupInput, idem *Idem) (Reply[*GroupDTO], error) {
	if _, err := s.require(ctx, actor, org, orgScope, "group:manage"); err != nil {
		return Reply[*GroupDTO]{}, err
	}
	cur, err := s.loadGroup(ctx, s.q(), org, id)
	if err != nil {
		return Reply[*GroupDTO]{}, Normalize(err)
	}
	fields := map[string]string{}
	if in.Slug != "" && in.Slug != cur.Slug {
		fields["slug"] = "the slug of a group cannot change"
	}
	name, desc := cur.Name, cur.Description
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
		if name == "" || len(name) > 80 {
			fields["name"] = "required, at most 80 characters"
		}
	}
	if in.Description != nil {
		desc = *in.Description
		if len(desc) > 500 {
			fields["description"] = "at most 500 characters"
		}
	}
	if len(fields) > 0 {
		return Reply[*GroupDTO]{}, validation(fields)
	}
	return doWrite(ctx, s, org, actor, idem, 200, func(tx pgx.Tx) (*GroupDTO, error) {
		tag, err := tx.Exec(ctx, `UPDATE groups SET name = $3, description = $4 WHERE id = $1 AND org_id = $2`, id, org, name, desc)
		if err != nil {
			return nil, mapPg(err)
		}
		if tag.RowsAffected() == 0 {
			return nil, domain.ErrNotFound
		}
		if name != cur.Name || desc != cur.Description {
			if err := s.audit(ctx, tx, org, actor, auditRow{Action: "access.group.updated", ResourceType: "group", ResourceID: id,
				Old: map[string]any{"name": cur.Name, "description": cur.Description}, New: map[string]any{"name": name, "description": desc}}); err != nil {
				return nil, err
			}
		}
		return s.loadGroup(ctx, tx, org, id)
	})
}

// ArchiveGroup archives a group: its assignments stop counting at once (group:manage). Idempotent.
func (s *Service) ArchiveGroup(ctx context.Context, actor Actor, org, id uuid.UUID, idem *Idem) (Reply[struct{}], error) {
	if _, err := s.require(ctx, actor, org, orgScope, "group:manage"); err != nil {
		return Reply[struct{}]{}, err
	}
	cur, err := s.loadGroup(ctx, s.q(), org, id)
	if err != nil {
		return Reply[struct{}]{}, Normalize(err)
	}
	return doWrite(ctx, s, org, actor, idem, 204, func(tx pgx.Tx) (struct{}, error) {
		tag, err := tx.Exec(ctx, `UPDATE groups SET archived_at = now() WHERE id = $1 AND org_id = $2 AND archived_at IS NULL`, id, org)
		if err != nil {
			return struct{}{}, mapPg(err)
		}
		if tag.RowsAffected() == 0 {
			return struct{}{}, nil // already archived
		}
		return struct{}{}, s.audit(ctx, tx, org, actor, auditRow{Action: "access.group.archived", ResourceType: "group", ResourceID: id,
			Old: map[string]any{"slug": cur.Slug, "archived": false}, New: map[string]any{"slug": cur.Slug, "archived": true}, Impact: cur.Members})
	})
}

func (s *Service) listGroupMembers(ctx context.Context, q querier, org, group uuid.UUID, cursor string, limit int) (*GroupMemberPage, error) {
	limit = clampLimit(limit)
	at, id, ok := decodeCursor(cursor)
	var afterAt time.Time
	var afterID uuid.UUID
	if ok {
		t, err := time.Parse(time.RFC3339Nano, at)
		u, err2 := uuid.Parse(id)
		if err == nil && err2 == nil {
			afterAt, afterID = t, u
		} else {
			ok = false
		}
	}
	rows, err := q.Query(ctx, `
		SELECT u.id, u.email, u.name, gm.source, gm.added_at, gm.expires_at
		  FROM group_members gm JOIN groups g ON g.id = gm.group_id AND g.org_id = $2 JOIN users u ON u.id = gm.user_id
		 WHERE gm.group_id = $1 AND (NOT $3 OR (gm.added_at, gm.user_id) > ($4, $5))
		 ORDER BY gm.added_at, gm.user_id LIMIT $6`, group, org, ok, afterAt, afterID, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &GroupMemberPage{Data: []GroupMemberDTO{}}
	for rows.Next() {
		var m GroupMemberDTO
		if err := rows.Scan(&m.User.ID, &m.User.Email, &m.User.Name, &m.Source, &m.AddedAt, &m.ExpiresAt); err != nil {
			return nil, err
		}
		page.Data = append(page.Data, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(page.Data) > limit {
		page.Data = page.Data[:limit]
		last := page.Data[limit-1]
		c := encodeCursor(last.AddedAt.UTC().Format(time.RFC3339Nano), last.User.ID.String())
		page.NextCursor = &c
	}
	return page, nil
}

// ListGroupMembers returns the members of a group (group:read).
func (s *Service) ListGroupMembers(ctx context.Context, actor Actor, org, id uuid.UUID, cursor string, limit int) (*GroupMemberPage, error) {
	if _, err := s.require(ctx, actor, org, orgScope, "group:read"); err != nil {
		return nil, err
	}
	if _, err := s.loadGroup(ctx, s.q(), org, id); err != nil {
		return nil, Normalize(err)
	}
	return s.listGroupMembers(ctx, s.q(), org, id, cursor, limit)
}

// AddGroupMembers adds people to a group (group:manage). Membership is a grant (SPEC 13.1): the actor must contain, at the scope of every
// live assignment of the group, the permissions of its template, and nobody but an owner adds themselves to a group that grants anything.
func (s *Service) AddGroupMembers(ctx context.Context, actor Actor, org, id uuid.UUID, in AddMembersInput, idem *Idem) (Reply[*GroupMemberPage], error) {
	if _, err := s.require(ctx, actor, org, orgScope, "group:manage"); err != nil {
		return Reply[*GroupMemberPage]{}, err
	}
	g, err := s.loadGroup(ctx, s.q(), org, id)
	if err != nil {
		return Reply[*GroupMemberPage]{}, Normalize(err)
	}
	if len(in.UserIDs) == 0 || len(in.UserIDs) > 100 {
		return Reply[*GroupMemberPage]{}, validationField("user_ids", "between 1 and 100 users")
	}
	if g.Archived {
		return Reply[*GroupMemberPage]{}, conflict("GROUP_ARCHIVED", "group is archived", nil)
	}
	if err := s.checkExpiry(ctx, s.q(), org, "expires_at", in.ExpiresAt); err != nil {
		return Reply[*GroupMemberPage]{}, err
	}
	uniq := map[uuid.UUID]bool{}
	var users []uuid.UUID
	for _, u := range in.UserIDs {
		if !uniq[u] {
			uniq[u] = true
			users = append(users, u)
		}
	}
	rows, err := s.q().Query(ctx, `SELECT user_id FROM org_members WHERE org_id = $1 AND user_id = ANY($2)`, org, users)
	if err != nil {
		return Reply[*GroupMemberPage]{}, err
	}
	isMember := map[uuid.UUID]bool{}
	for rows.Next() {
		var u uuid.UUID
		if err := rows.Scan(&u); err != nil {
			rows.Close()
			return Reply[*GroupMemberPage]{}, err
		}
		isMember[u] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Reply[*GroupMemberPage]{}, err
	}
	bad := map[string]string{}
	for i, u := range in.UserIDs {
		if !isMember[u] {
			bad[fmt.Sprintf("user_ids[%d]", i)] = "not a member of the organization"
		}
	}
	if len(bad) > 0 {
		return Reply[*GroupMemberPage]{}, validation(bad)
	}
	owner, err := s.isOwner(ctx, s.q(), org, actor.UserID)
	if err != nil {
		return Reply[*GroupMemberPage]{}, err
	}
	if !owner {
		asg, err := s.liveGroupAssignments(ctx, s.q(), org, id)
		if err != nil {
			return Reply[*GroupMemberPage]{}, err
		}
		if len(asg) > 0 {
			if uniq[actor.UserID] {
				return Reply[*GroupMemberPage]{}, escalation("you cannot add yourself to a group that grants access", nil, "self_grant")
			}
			var missing catalog.Set
			for _, a := range asg {
				m, err := s.containmentMissing(ctx, actor, org, a.ScopeType, a.ScopeID, a.Perms)
				if err != nil {
					return Reply[*GroupMemberPage]{}, err
				}
				missing = missing.Union(m)
			}
			if !missing.IsEmpty() {
				return Reply[*GroupMemberPage]{}, escalation("adding members to this group grants permissions you do not hold", missing.IDs(), "")
			}
		}
	}
	return doWrite(ctx, s, org, actor, idem, 200, func(tx pgx.Tx) (*GroupMemberPage, error) {
		var archived *time.Time
		if err := tx.QueryRow(ctx, `SELECT archived_at FROM groups WHERE id = $1 AND org_id = $2 FOR UPDATE`, id, org).Scan(&archived); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, domain.ErrNotFound
			}
			return nil, err
		}
		if archived != nil {
			return nil, conflict("GROUP_ARCHIVED", "group is archived", nil)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM group_members WHERE group_id = $1 AND NOT (user_id = ANY($2))`, id, users).Scan(&n); err != nil {
			return nil, err
		}
		if n+len(users) > repository.MaxGroupMembers {
			return nil, limitErr(fmt.Sprintf("a group has at most %d members", repository.MaxGroupMembers))
		}
		for _, u := range users {
			var oldExp *time.Time
			existed := false
			err := tx.QueryRow(ctx, `SELECT expires_at FROM group_members WHERE group_id = $1 AND user_id = $2`, id, u).Scan(&oldExp)
			if err == nil {
				existed = true
			} else if !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO group_members (group_id, user_id, source, added_by, expires_at) VALUES ($1,$2,'manual',$3,$4)
				ON CONFLICT (group_id, user_id) DO UPDATE SET expires_at = EXCLUDED.expires_at`, id, u, actor.UserID, in.ExpiresAt); err != nil {
				return nil, mapPg(err)
			}
			nv := map[string]any{"group_id": id.String(), "group": g.Slug, "user_id": u.String(), "subject_id": u.String(), "expires_at": in.ExpiresAt}
			var ov map[string]any
			if existed {
				ov = map[string]any{"group_id": id.String(), "user_id": u.String(), "expires_at": oldExp}
			}
			if err := s.audit(ctx, tx, org, actor, auditRow{Action: "access.group_member.added", ResourceType: "group_member", ResourceID: id, Old: ov, New: nv, Impact: 1}); err != nil {
				return nil, err
			}
		}
		return s.listGroupMembers(ctx, tx, org, id, "", 200)
	})
}

// RemoveGroupMember removes a person from a group (group:manage). Removing never needs containment.
func (s *Service) RemoveGroupMember(ctx context.Context, actor Actor, org, id, user uuid.UUID, idem *Idem) (Reply[struct{}], error) {
	if _, err := s.require(ctx, actor, org, orgScope, "group:manage"); err != nil {
		return Reply[struct{}]{}, err
	}
	g, err := s.loadGroup(ctx, s.q(), org, id)
	if err != nil {
		return Reply[struct{}]{}, Normalize(err)
	}
	return doWrite(ctx, s, org, actor, idem, 204, func(tx pgx.Tx) (struct{}, error) {
		var oldExp *time.Time
		err := tx.QueryRow(ctx, `
			DELETE FROM group_members gm USING groups gr WHERE gm.group_id = gr.id AND gr.id = $1 AND gr.org_id = $2 AND gm.user_id = $3
			RETURNING gm.expires_at`, id, org, user).Scan(&oldExp)
		if errors.Is(err, pgx.ErrNoRows) {
			return struct{}{}, notFound("membership not found")
		}
		if err != nil {
			return struct{}{}, mapPg(err)
		}
		return struct{}{}, s.audit(ctx, tx, org, actor, auditRow{Action: "access.group_member.removed", ResourceType: "group_member", ResourceID: id,
			Old: map[string]any{"group_id": id.String(), "group": g.Slug, "user_id": user.String(), "subject_id": user.String(), "expires_at": oldExp}, Impact: 1})
	})
}
