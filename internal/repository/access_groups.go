package repository

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kynto/capsule/backend/internal/domain"
)

var groupSlugRE = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// AccessGroup is a flat group of an organization.
type AccessGroup struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	Slug        string
	Name        string
	Description string
	Source      string // manual | oidc
	ExternalRef string
	ArchivedAt  *time.Time
	CreatedBy   *uuid.UUID
	CreatedAt   time.Time
}

// AccessGroupMember is a group membership.
type AccessGroupMember struct {
	GroupID   uuid.UUID
	UserID    uuid.UUID
	Source    string
	AddedBy   *uuid.UUID
	AddedAt   time.Time
	ExpiresAt *time.Time
}

const groupCols = `id, org_id, slug, name, description, source, external_ref, archived_at, created_by, created_at`

func scanGroup(row rowScanner, g *AccessGroup) error {
	return row.Scan(&g.ID, &g.OrgID, &g.Slug, &g.Name, &g.Description, &g.Source, &g.ExternalRef, &g.ArchivedAt, &g.CreatedBy, &g.CreatedAt)
}

// NewGroup is the input of CreateGroup.
type NewGroup struct {
	Slug        string
	Name        string
	Description string
	Source      string // "" = manual
	ExternalRef string
	CreatedBy   *uuid.UUID
}

// CreateGroup creates a group (at most MaxGroupsPerOrg per organization, slug unique per organization).
func (s *AccessStore) CreateGroup(ctx context.Context, orgID uuid.UUID, in NewGroup) (*AccessGroup, error) {
	if !groupSlugRE.MatchString(in.Slug) || strings.TrimSpace(in.Name) == "" {
		return nil, fmt.Errorf("%w: group slug or name", ErrAccessInvalid)
	}
	if in.Source == "" {
		in.Source = "manual"
	}
	var g AccessGroup
	err := s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM groups WHERE org_id = $1`, orgID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxGroupsPerOrg {
			return fmt.Errorf("%w: %d groups per organization", ErrAccessLimit, MaxGroupsPerOrg)
		}
		return mapAccessErr(scanGroup(tx.QueryRow(ctx, `
			INSERT INTO groups (org_id, slug, name, description, source, external_ref, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+groupCols,
			orgID, in.Slug, in.Name, in.Description, in.Source, in.ExternalRef, in.CreatedBy), &g))
	})
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// ArchiveGroup archives a group: its assignments stop counting immediately (the snapshot query skips archived groups).
func (s *AccessStore) ArchiveGroup(ctx context.Context, orgID, groupID uuid.UUID) error {
	return s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE groups SET archived_at = coalesce(archived_at, now()) WHERE id = $1 AND org_id = $2`, groupID, orgID)
		if err != nil {
			return mapAccessErr(err)
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

// GetGroup returns a group of the organization.
func (s *AccessStore) GetGroup(ctx context.Context, orgID, groupID uuid.UUID) (*AccessGroup, error) {
	var g AccessGroup
	err := scanGroup(s.pool.QueryRow(ctx, `SELECT `+groupCols+` FROM groups WHERE id = $1 AND org_id = $2`, groupID, orgID), &g)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("getting group: %w", err)
	}
	return &g, nil
}

// ListGroupMembers lists the members of a group of the organization.
func (s *AccessStore) ListGroupMembers(ctx context.Context, orgID, groupID uuid.UUID) ([]AccessGroupMember, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT gm.group_id, gm.user_id, gm.source, gm.added_by, gm.added_at, gm.expires_at
		  FROM group_members gm JOIN groups g ON g.id = gm.group_id
		 WHERE gm.group_id = $1 AND g.org_id = $2 ORDER BY gm.added_at`, groupID, orgID)
	if err != nil {
		return nil, fmt.Errorf("listing group members: %w", err)
	}
	defer rows.Close()
	var out []AccessGroupMember
	for rows.Next() {
		var m AccessGroupMember
		if err := rows.Scan(&m.GroupID, &m.UserID, &m.Source, &m.AddedBy, &m.AddedAt, &m.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AddGroupMember adds (or re-dates) a member. The user must belong to the organization; the group must not be archived; at most
// MaxGroupMembers per group. The no-escalation rule (SPEC 13.1) is checked by the service before calling this.
func (s *AccessStore) AddGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID, source string, addedBy *uuid.UUID, expiresAt *time.Time) error {
	if source == "" {
		source = "manual"
	}
	return s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		var archived *time.Time
		if err := tx.QueryRow(ctx, `SELECT archived_at FROM groups WHERE id = $1 AND org_id = $2 FOR UPDATE`, groupID, orgID).Scan(&archived); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrNotFound
			}
			return err
		}
		if archived != nil {
			return fmt.Errorf("%w: group is archived", ErrAccessInvalid)
		}
		var isMember bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2)`, orgID, userID).Scan(&isMember); err != nil {
			return err
		}
		if !isMember {
			return fmt.Errorf("%w: user is not a member of the organization", ErrAccessInvalid)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM group_members WHERE group_id = $1 AND user_id <> $2`, groupID, userID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxGroupMembers {
			return fmt.Errorf("%w: %d members per group", ErrAccessLimit, MaxGroupMembers)
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO group_members (group_id, user_id, source, added_by, expires_at) VALUES ($1,$2,$3,$4,$5)
			ON CONFLICT (group_id, user_id) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
			groupID, userID, source, addedBy, expiresAt)
		return mapAccessErr(err)
	})
}

// RemoveGroupMember removes a membership; ErrNotFound if it did not exist.
func (s *AccessStore) RemoveGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID) error {
	return s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			DELETE FROM group_members gm USING groups g
			 WHERE gm.group_id = g.id AND g.id = $1 AND g.org_id = $2 AND gm.user_id = $3`, groupID, orgID, userID)
		if err != nil {
			return mapAccessErr(err)
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}
