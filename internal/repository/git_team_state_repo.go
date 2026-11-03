package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitsync"
)

// GitTeamStateRepository persists git_team_state (Git Capsule A2) and lists Forgejo-linked projects.
type GitTeamStateRepository struct{ pool *pgxpool.Pool }

func NewGitTeamStateRepository(pool *pgxpool.Pool) *GitTeamStateRepository {
	return &GitTeamStateRepository{pool: pool}
}

var _ gitsync.StateStore = (*GitTeamStateRepository)(nil)

const gitTeamStateCols = `project_id, role, team_id, team_name, permission, members, last_synced_at, last_error,
	drift_events, last_drift_at, last_drift_added, last_drift_removed`

func scanGitTeamState(row interface{ Scan(...any) error }, s *gitsync.TeamState) error {
	var role string
	if err := row.Scan(&s.ProjectID, &role, &s.TeamID, &s.TeamName, &s.Permission, &s.Members, &s.LastSyncedAt, &s.LastError,
		&s.DriftEvents, &s.LastDriftAt, &s.LastDriftAdded, &s.LastDriftRemoved); err != nil {
		return err
	}
	s.Role = authz.Role(role)
	return nil
}

func (r *GitTeamStateRepository) PutTeamState(ctx context.Context, st gitsync.TeamState, drift bool) error {
	inc := 0
	if drift {
		inc = 1
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO git_team_state (project_id, role, team_id, team_name, permission, members, last_synced_at, last_error,
			drift_events, last_drift_at, last_drift_added, last_drift_removed)
		VALUES ($1,$2,$3,$4,$5,$6,$7::timestamptz,$8,$9::int, CASE WHEN $10::boolean THEN $7::timestamptz END, CASE WHEN $10::boolean THEN $11::int ELSE 0 END, CASE WHEN $10::boolean THEN $12::int ELSE 0 END)
		ON CONFLICT (project_id, role) DO UPDATE SET
			team_id = EXCLUDED.team_id, team_name = EXCLUDED.team_name, permission = EXCLUDED.permission,
			members = EXCLUDED.members, last_synced_at = EXCLUDED.last_synced_at, last_error = EXCLUDED.last_error,
			drift_events = git_team_state.drift_events + $9::int,
			last_drift_at = CASE WHEN $10::boolean THEN EXCLUDED.last_synced_at ELSE git_team_state.last_drift_at END,
			last_drift_added = CASE WHEN $10::boolean THEN $11::int ELSE git_team_state.last_drift_added END,
			last_drift_removed = CASE WHEN $10::boolean THEN $12::int ELSE git_team_state.last_drift_removed END`,
		st.ProjectID, string(st.Role), st.TeamID, st.TeamName, st.Permission, st.Members, st.LastSyncedAt, st.LastError,
		inc, drift, st.LastDriftAdded, st.LastDriftRemoved)
	if err != nil {
		return fmt.Errorf("saving git team state: %w", err)
	}
	return nil
}

func (r *GitTeamStateRepository) ListTeamStates(ctx context.Context, projectID uuid.UUID) ([]gitsync.TeamState, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+gitTeamStateCols+` FROM git_team_state WHERE project_id = $1 ORDER BY role`, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing git team state: %w", err)
	}
	defer rows.Close()
	var out []gitsync.TeamState
	for rows.Next() {
		var s gitsync.TeamState
		if err := scanGitTeamState(rows, &s); err != nil {
			return nil, fmt.Errorf("scanning git team state: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *GitTeamStateRepository) ListForgejoProjects(ctx context.Context, after uuid.UUID, limit int) ([]uuid.UUID, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, `
		SELECT p.id FROM projects p JOIN project_git g ON g.project_id = p.id
		WHERE g.provider = 'forgejo' AND p.deleted_at IS NULL AND p.id > $1
		ORDER BY p.id LIMIT $2`, after, limit)
	if err != nil {
		return nil, fmt.Errorf("listing forgejo projects: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scanning forgejo project: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (r *GitTeamStateRepository) AuditDrift(ctx context.Context, orgID, projectID uuid.UUID, action string, values map[string]any) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO audit_logs (user_id, org_id, action, resource_type, resource_id, new_values)
		VALUES (NULL, $1, $2, 'project', $3, $4)`, orgID, action, projectID, values)
	if err != nil {
		return fmt.Errorf("writing drift audit: %w", err)
	}
	return nil
}
