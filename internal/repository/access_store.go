package repository

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
)

// AccessStore is the Postgres side of the permission engine (docs/permissions/SPEC.md sections 12 and 14):
//
//   - read side: everything the evaluator needs to compile a snapshot for (user, organization), each method one indexed query;
//   - write side: transactional commands. Every command runs inside InTx, which locks the organization row, increments
//     organizations.access_epoch and executes NOTIFY capsule_access in the SAME transaction (the NOTIFY is delivered on commit).
//
// P1 (internal/authz/engine) defines the engine.Store interface. Until it exists AccessStore exposes the read side through
// AccessSource below, which is the minimal contract; the adapter to engine.Store is a few lines of type mapping (see P2-NOTES.md).
type AccessStore struct{ pool *pgxpool.Pool }

func NewAccessStore(pool *pgxpool.Pool) *AccessStore { return &AccessStore{pool: pool} }

// Pool returns the underlying pool (tests and the notify listener).
func (s *AccessStore) Pool() *pgxpool.Pool { return s.pool }

// AccessNotifyChannel is the Postgres LISTEN/NOTIFY channel; the payload is the organization id.
const AccessNotifyChannel = "capsule_access"

// Limits of SPEC 13.4. Exceeding one is ErrAccessLimit (the API answers 422).
const (
	MaxTemplatesPerOrg   = 200
	MaxPermsPerTemplate  = 200
	MaxGroupsPerOrg      = 500
	MaxGroupMembers      = 5000
	MaxAssignmentsPerOrg = 100000
)

var (
	ErrSystemTemplate   = errors.New("system templates are immutable")
	ErrTemplateArchived = errors.New("template is archived")
	ErrTemplateInUse    = errors.New("template is in use")
	ErrReservedSlug     = errors.New("slug is reserved by a system template")
	ErrAccessLimit      = errors.New("access limit exceeded")
	ErrAccessConflict   = errors.New("access record already exists")
	ErrAccessInvalid    = errors.New("invalid access data")
)

// AccessSource is the read contract the evaluator needs (the shape P1's engine.Store is expected to take).
type AccessSource interface {
	LoadMembership(ctx context.Context, orgID, userID uuid.UUID) (*AccessMembership, error)
	LoadOrgPolicy(ctx context.Context, orgID uuid.UUID) (*AccessOrgPolicy, error)
	LoadProjectOverrides(ctx context.Context, orgID uuid.UUID) (map[uuid.UUID]string, error)
	LoadUserAssignments(ctx context.Context, orgID, userID uuid.UUID) ([]AccessAssignment, error)
	LoadTemplateVersions(ctx context.Context, refs []TemplateRef) (map[TemplateRef]*AccessTemplateVersion, error)
	EnvReviewers(ctx context.Context, envID uuid.UUID) (projectID uuid.UUID, reviewers json.RawMessage, err error)
	Epochs(ctx context.Context, orgID, userID uuid.UUID) (orgEpoch, userEpoch int64, err error)
}

var _ AccessSource = (*AccessStore)(nil)

// AccessMembership is the state of a user in an organization. LoadMembership returns nil when the user is not a member.
type AccessMembership struct {
	OrgID, UserID   uuid.UUID
	LegacyRole      string     // org_members.role (legacy label)
	Status          string     // org_members.status: active | suspended
	TemplateID      *uuid.UUID // nil: the role does not resolve (closes: no access)
	TemplateVersion *int       // nil: follow the latest version
	UserStatus      string     // users.status
	PlatformRole    string     // users.platform_role
	UserEpoch       int64
}

// AccessOrgPolicy is the organization-level policy.
type AccessOrgPolicy struct {
	OrgID    uuid.UUID
	Mode     string // open | restricted (project_access_mode)
	Epoch    int64
	Settings json.RawMessage // access_settings
}

// AccessAssignment is one live (not revoked) assignment. Expired rows are returned too: the evaluator applies its own clock.
// LoadUserAssignments fills the lean subset (no Reason, CreatedBy, CreatedAt); LoadAssignmentDetails and the list methods fill all.
type AccessAssignment struct {
	ID            uuid.UUID
	OrgID         uuid.UUID
	SubjectType   string // user | group
	SubjectID     uuid.UUID
	ScopeType     string // org | project | repo | env
	ScopeID       uuid.UUID
	TemplateID    uuid.UUID
	PinnedVersion *int
	Source        string
	Reason        string
	ExpiresAt     *time.Time
	CreatedBy     *uuid.UUID
	CreatedAt     time.Time
	// ViaGroup is set when the assignment reaches the user through a group; GroupExpiresAt is that membership's expiry.
	ViaGroup       *uuid.UUID
	GroupExpiresAt *time.Time
}

// TemplateRef names a template version; Version 0 means the current (latest) one.
type TemplateRef struct {
	ID      uuid.UUID
	Version int
}

// AccessTemplate is the template header.
type AccessTemplate struct {
	ID             uuid.UUID
	OrgID          *uuid.UUID // nil for system templates
	Kind           string
	Slug           string
	Name           string
	Description    string
	System         bool
	ClonedFrom     *uuid.UUID
	CurrentVersion int
	ArchivedAt     *time.Time
	CreatedBy      *uuid.UUID
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// AccessTemplateVersion is one immutable version with its header facts.
type AccessTemplateVersion struct {
	TemplateID      uuid.UUID
	OrgID           *uuid.UUID
	Kind            string
	Slug            string
	System          bool
	Archived        bool
	Version         int
	Permissions     []string
	Ceiling         []string // nil: no ceiling. Cap at organization scope
	CeilingProject  []string // cap at project, repo and env scope (organization templates with a ceiling)
	FloorTemplateID *uuid.UUID
	BaseTemplateID  *uuid.UUID
	Note            string
	CreatedBy       *uuid.UUID
	CreatedAt       time.Time
}

// ---------------------------------------------------------------- read side

func (s *AccessStore) LoadMembership(ctx context.Context, orgID, userID uuid.UUID) (*AccessMembership, error) {
	m := &AccessMembership{OrgID: orgID, UserID: userID}
	err := s.pool.QueryRow(ctx, `
		SELECT om.role, om.status, om.template_id, om.template_version, u.status, u.platform_role, u.access_epoch
		  FROM org_members om
		  JOIN organizations o ON o.id = om.org_id AND o.deleted_at IS NULL
		  JOIN users u ON u.id = om.user_id
		 WHERE om.org_id = $1 AND om.user_id = $2`, orgID, userID).
		Scan(&m.LegacyRole, &m.Status, &m.TemplateID, &m.TemplateVersion, &m.UserStatus, &m.PlatformRole, &m.UserEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading membership: %w", err)
	}
	return m, nil
}

func (s *AccessStore) LoadOrgPolicy(ctx context.Context, orgID uuid.UUID) (*AccessOrgPolicy, error) {
	p := &AccessOrgPolicy{OrgID: orgID}
	err := s.pool.QueryRow(ctx, `SELECT project_access_mode, access_epoch, access_settings FROM organizations WHERE id = $1 AND deleted_at IS NULL`, orgID).
		Scan(&p.Mode, &p.Epoch, &p.Settings)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading org policy: %w", err)
	}
	return p, nil
}

// LoadProjectOverrides returns projects of the organization that override the policy (access_override IS NOT NULL).
func (s *AccessStore) LoadProjectOverrides(ctx context.Context, orgID uuid.UUID) (map[uuid.UUID]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, access_override FROM projects WHERE org_id = $1 AND access_override IS NOT NULL AND deleted_at IS NULL`, orgID)
	if err != nil {
		return nil, fmt.Errorf("loading project overrides: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]string{}
	for rows.Next() {
		var id uuid.UUID
		var mode string
		if err := rows.Scan(&id, &mode); err != nil {
			return nil, err
		}
		out[id] = mode
	}
	return out, rows.Err()
}

const assignmentCols = `a.id, a.org_id, a.subject_type, a.subject_id, a.scope_type, a.scope_id, a.template_id, a.pinned_version,
	a.source, a.reason, a.expires_at, a.created_by, a.created_at`

// scanAssignment scans uuids as [16]byte / pgtype.UUID: google/uuid implements sql.Scanner through its TEXT form, which is
// several times slower for the 10 000 rows of a big snapshot.
func scanAssignment(row rowScanner, a *AccessAssignment, withVia bool) error {
	var id, org, subj, scope, tpl [16]byte
	var createdBy, via pgtype.UUID
	dst := []any{&id, &org, &a.SubjectType, &subj, &a.ScopeType, &scope, &tpl, &a.PinnedVersion,
		&a.Source, &a.Reason, &a.ExpiresAt, &createdBy, &a.CreatedAt}
	if withVia {
		dst = append(dst, &via, &a.GroupExpiresAt)
	}
	if err := row.Scan(dst...); err != nil {
		return err
	}
	a.ID, a.OrgID, a.SubjectID, a.ScopeID, a.TemplateID = id, org, subj, scope, tpl
	a.CreatedBy, a.ViaGroup = nil, nil
	if createdBy.Valid {
		v := uuid.UUID(createdBy.Bytes)
		a.CreatedBy = &v
	}
	if via.Valid {
		v := uuid.UUID(via.Bytes)
		a.ViaGroup = &v
	}
	return nil
}

// snapshotCols are the columns the evaluator needs per assignment (the lean form: no reason, creator or creation time, which only
// the explain trace shows and which LoadAssignmentDetails fetches by id). Decoding 10 000 rows is most of the snapshot cost.
const snapshotCols = `a.id, a.subject_type, a.subject_id, a.scope_type, a.scope_id, a.template_id, a.pinned_version, a.source, a.expires_at`

// loadUserAssignmentsSQL is the snapshot query ($1 org, $2 user); a test runs EXPLAIN on exactly this text.
const loadUserAssignmentsSQL = `
	SELECT ` + snapshotCols + `, NULL::uuid, NULL::timestamptz
	  FROM access_assignments a
	 WHERE a.org_id = $1 AND a.revoked_at IS NULL AND a.subject_type = 'user' AND a.subject_id = $2
	UNION ALL
	SELECT ` + snapshotCols + `, g.id, gm.expires_at
	  FROM group_members gm
	  JOIN groups g ON g.id = gm.group_id AND g.org_id = $1 AND g.archived_at IS NULL
	  JOIN access_assignments a ON a.org_id = $1 AND a.revoked_at IS NULL AND a.subject_type = 'group' AND a.subject_id = g.id
	 WHERE gm.user_id = $2`

// LoadUserAssignments returns, in ONE query, the live assignments of the user and of every non-archived group the user belongs to
// (each group row carries ViaGroup and the membership expiry). Both branches use idx_access_assign_subject.
func (s *AccessStore) LoadUserAssignments(ctx context.Context, orgID, userID uuid.UUID) ([]AccessAssignment, error) {
	rows, err := s.pool.Query(ctx, loadUserAssignmentsSQL, orgID, userID)
	if err != nil {
		return nil, fmt.Errorf("loading user assignments: %w", err)
	}
	defer rows.Close()
	out := make([]AccessAssignment, 0, 64)
	fast := false
	for rows.Next() {
		if len(out) == 0 {
			fast = snapshotRawBinary(rows.FieldDescriptions())
		}
		a := AccessAssignment{OrgID: orgID}
		if fast {
			if err := decodeSnapshotRow(rows.RawValues(), &a); err != nil {
				return nil, err
			}
		} else {
			var id, subj, scope, tpl [16]byte
			var via pgtype.UUID
			if err := rows.Scan(&id, &a.SubjectType, &subj, &a.ScopeType, &scope, &tpl, &a.PinnedVersion, &a.Source, &a.ExpiresAt, &via, &a.GroupExpiresAt); err != nil {
				return nil, fmt.Errorf("scanning assignment: %w", err)
			}
			a.ID, a.SubjectID, a.ScopeID, a.TemplateID = id, subj, scope, tpl
			if via.Valid {
				v := uuid.UUID(via.Bytes)
				a.ViaGroup = &v
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// snapshotRawBinary reports whether the columns of the snapshot query arrive in the binary format RawValues decoding assumes.
func snapshotRawBinary(fds []pgconn.FieldDescription) bool {
	if len(fds) != 11 {
		return false
	}
	for _, i := range []int{0, 2, 4, 5, 6, 8, 9, 10} { // uuid, uuid, uuid, uuid, int4, timestamptz, uuid, timestamptz
		if fds[i].Format != pgtype.BinaryFormatCode {
			return false
		}
	}
	return true
}

var pgEpoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

func rawUUID(b []byte) (uuid.UUID, error) {
	var u uuid.UUID
	if len(b) != 16 {
		return u, fmt.Errorf("uuid column of %d bytes", len(b))
	}
	copy(u[:], b)
	return u, nil
}

func rawTime(b []byte) (*time.Time, error) {
	if b == nil {
		return nil, nil
	}
	if len(b) != 8 {
		return nil, fmt.Errorf("timestamptz column of %d bytes", len(b))
	}
	t := pgEpoch.Add(time.Duration(int64(binary.BigEndian.Uint64(b))) * time.Microsecond)
	return &t, nil
}

// internStr returns a constant for the few values these columns take, so decoding 10 000 rows allocates no strings.
func internStr(b []byte) string {
	switch string(b) {
	case "user":
		return "user"
	case "group":
		return "group"
	case "org":
		return "org"
	case "project":
		return "project"
	case "repo":
		return "repo"
	case "env":
		return "env"
	case "manual":
		return "manual"
	case "migrated":
		return "migrated"
	case "legacy-api":
		return "legacy-api"
	case "approver":
		return "approver"
	case "oidc":
		return "oidc"
	case "temporary":
		return "temporary"
	}
	return string(b)
}

// decodeSnapshotRow decodes the binary RawValues of one row of loadUserAssignmentsSQL.
func decodeSnapshotRow(v [][]byte, a *AccessAssignment) error {
	var err error
	if a.ID, err = rawUUID(v[0]); err != nil {
		return err
	}
	a.SubjectType = internStr(v[1])
	if a.SubjectID, err = rawUUID(v[2]); err != nil {
		return err
	}
	a.ScopeType = internStr(v[3])
	if a.ScopeID, err = rawUUID(v[4]); err != nil {
		return err
	}
	if a.TemplateID, err = rawUUID(v[5]); err != nil {
		return err
	}
	if v[6] != nil {
		if len(v[6]) != 4 {
			return fmt.Errorf("int4 column of %d bytes", len(v[6]))
		}
		n := int(int32(binary.BigEndian.Uint32(v[6])))
		a.PinnedVersion = &n
	}
	a.Source = internStr(v[7])
	if a.ExpiresAt, err = rawTime(v[8]); err != nil {
		return err
	}
	if v[9] != nil {
		g, err := rawUUID(v[9])
		if err != nil {
			return err
		}
		a.ViaGroup = &g
	}
	a.GroupExpiresAt, err = rawTime(v[10])
	return err
}

// LoadAssignmentDetails returns the full rows (reason, creator, creation time) of assignments by id, for the explain trace.
func (s *AccessStore) LoadAssignmentDetails(ctx context.Context, orgID uuid.UUID, ids []uuid.UUID) (map[uuid.UUID]AccessAssignment, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+assignmentCols+` FROM access_assignments a WHERE a.org_id = $1 AND a.id = ANY($2)`, orgID, ids)
	if err != nil {
		return nil, fmt.Errorf("loading assignment details: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]AccessAssignment{}
	for rows.Next() {
		var a AccessAssignment
		if err := scanAssignment(rows, &a, false); err != nil {
			return nil, err
		}
		out[a.ID] = a
	}
	return out, rows.Err()
}

// LoadTemplateVersions resolves many (template, version) refs in one query. Refs that do not resolve are absent from the result
// (the evaluator closes on them). The map key is the ref as requested (Version 0 stays 0).
func (s *AccessStore) LoadTemplateVersions(ctx context.Context, refs []TemplateRef) (map[TemplateRef]*AccessTemplateVersion, error) {
	out := make(map[TemplateRef]*AccessTemplateVersion, len(refs))
	if len(refs) == 0 {
		return out, nil
	}
	ids := make([]uuid.UUID, len(refs))
	vers := make([]int32, len(refs))
	for i, r := range refs {
		ids[i], vers[i] = r.ID, int32(r.Version)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT r.id, r.ver, t.org_id, t.kind, t.slug, t.system, t.archived_at IS NOT NULL,
		       v.version, v.permissions, v.ceiling, v.ceiling_project, v.floor_template_id, v.base_template_id, v.note, v.created_by, v.created_at
		  FROM unnest($1::uuid[], $2::int[]) AS r(id, ver)
		  JOIN role_templates t ON t.id = r.id
		  JOIN role_template_versions v ON v.template_id = t.id AND v.version = CASE WHEN r.ver = 0 THEN t.current_version ELSE r.ver END`, ids, vers)
	if err != nil {
		return nil, fmt.Errorf("loading template versions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v AccessTemplateVersion
		var req int32
		if err := rows.Scan(&v.TemplateID, &req, &v.OrgID, &v.Kind, &v.Slug, &v.System, &v.Archived,
			&v.Version, &v.Permissions, &v.Ceiling, &v.CeilingProject, &v.FloorTemplateID, &v.BaseTemplateID, &v.Note, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning template version: %w", err)
		}
		vv := v
		out[TemplateRef{ID: v.TemplateID, Version: int(req)}] = &vv
	}
	return out, rows.Err()
}

// EnvReviewers returns the owning project and the raw reviewers JSON of an environment (the approver adapter of MIGRATION sec. 2
// reads it; the format is environments.Reviewer: {type, user_id, role}).
func (s *AccessStore) EnvReviewers(ctx context.Context, envID uuid.UUID) (uuid.UUID, json.RawMessage, error) {
	var project uuid.UUID
	var rev json.RawMessage
	err := s.pool.QueryRow(ctx, `SELECT project_id, reviewers FROM environments WHERE id = $1`, envID).Scan(&project, &rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil, domain.ErrNotFound
	}
	if err != nil {
		return uuid.Nil, nil, fmt.Errorf("loading environment reviewers: %w", err)
	}
	return project, rev, nil
}

// Epochs reads access_epoch of the organization and of the user by primary key (the strict path of SPEC 12.2).
func (s *AccessStore) Epochs(ctx context.Context, orgID, userID uuid.UUID) (int64, int64, error) {
	var oe, ue int64
	err := s.pool.QueryRow(ctx, `
		SELECT (SELECT access_epoch FROM organizations WHERE id = $1), (SELECT access_epoch FROM users WHERE id = $2)`, orgID, userID).Scan(&oe, &ue)
	if err != nil {
		// a missing organization or user scans as NULL into int64
		return 0, 0, fmt.Errorf("loading epochs: %w", err)
	}
	return oe, ue, nil
}

// ---------------------------------------------------------------- write side

// InTx runs fn in a transaction that (1) locks the organization row, which serializes access writes per organization and makes
// "check then insert" limits and invariants safe, and (2) after fn increments organizations.access_epoch and executes
// NOTIFY capsule_access (access_bump_org) before commit. If fn returns an error nothing is written and nothing is notified.
// P4 and P5 compose their audit rows inside fn, so a failed audit rolls back the change (SPEC 11.3).
func (s *AccessStore) InTx(ctx context.Context, orgID uuid.UUID, fn func(tx pgx.Tx) error) error {
	_, err := s.inTx(ctx, orgID, fn)
	return err
}

// InTxEpoch is InTx and also returns the new organization epoch.
func (s *AccessStore) InTxEpoch(ctx context.Context, orgID uuid.UUID, fn func(tx pgx.Tx) error) (int64, error) {
	return s.inTx(ctx, orgID, fn)
}

func (s *AccessStore) inTx(ctx context.Context, orgID uuid.UUID, fn func(tx pgx.Tx) error) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var locked uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM organizations WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, orgID).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, domain.ErrNotFound
		}
		return 0, fmt.Errorf("locking organization: %w", err)
	}
	if err := fn(tx); err != nil {
		return 0, err
	}
	var epoch int64
	if err := tx.QueryRow(ctx, `SELECT access_bump_org($1)`, orgID).Scan(&epoch); err != nil {
		return 0, fmt.Errorf("bumping access epoch: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return epoch, nil
}

// BumpUser increments users.access_epoch and notifies every organization of the user (account-level changes: suspension, platform role).
func (s *AccessStore) BumpUser(ctx context.Context, userID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if tag, err := tx.Exec(ctx, `UPDATE users SET access_epoch = access_epoch + 1 WHERE id = $1`, userID); err != nil || tag.RowsAffected() == 0 {
		if err != nil {
			return fmt.Errorf("bumping user epoch: %w", err)
		}
		return domain.ErrNotFound
	}
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, org_id::text) FROM org_members WHERE user_id = $2`, AccessNotifyChannel, userID); err != nil {
		return fmt.Errorf("notifying: %w", err)
	}
	return tx.Commit(ctx)
}

// SetProjectAccessOverride sets or clears (nil) the per-project policy override. The project must belong to the organization.
func (s *AccessStore) SetProjectAccessOverride(ctx context.Context, orgID, projectID uuid.UUID, mode *string) error {
	return s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE projects SET access_override = $3 WHERE id = $2 AND org_id = $1 AND deleted_at IS NULL`, orgID, projectID, mode)
		if err != nil {
			return mapAccessErr(err)
		}
		if tag.RowsAffected() == 0 {
			return domain.ErrNotFound
		}
		return nil
	})
}

// SetOrgAccessMode sets organizations.project_access_mode (open | restricted) with epoch and notify.
func (s *AccessStore) SetOrgAccessMode(ctx context.Context, orgID uuid.UUID, mode string) error {
	return s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE organizations SET project_access_mode = $2, updated_at = now() WHERE id = $1`, orgID, mode)
		return mapAccessErr(err)
	})
}

// MergeOrgAccessSettings merges a JSON object into organizations.access_settings.
func (s *AccessStore) MergeOrgAccessSettings(ctx context.Context, orgID uuid.UUID, patch map[string]any) error {
	b, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAccessInvalid, err)
	}
	return s.InTx(ctx, orgID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE organizations SET access_settings = access_settings || $2::jsonb, updated_at = now() WHERE id = $1`, orgID, string(b))
		return mapAccessErr(err)
	})
}

// mapAccessErr turns constraint and trigger violations into the package errors; other errors pass through wrapped.
func mapAccessErr(err error) error {
	if err == nil {
		return nil
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "23505":
			return fmt.Errorf("%w: %s", ErrAccessConflict, pe.ConstraintName)
		case "23514", "23503", "22P02":
			return fmt.Errorf("%w: %s", ErrAccessInvalid, pe.Message)
		case "23001":
			return fmt.Errorf("%w: %s", ErrSystemTemplate, pe.Message)
		}
	}
	return err
}
