package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gittokens"
)

// GitAccessRepository persists git_access_tokens (000044), git_ssh_keys (000045, see
// git_ssh_keys_repo.go) and the audit rows of the Git access package (A7).
type GitAccessRepository struct{ pool *pgxpool.Pool }

// NewGitAccessRepository returns the repository over pool.
func NewGitAccessRepository(pool *pgxpool.Pool) *GitAccessRepository {
	return &GitAccessRepository{pool: pool}
}

var _ gittokens.Store = (*GitAccessRepository)(nil)

// gitTokenColumns are the SELECT expressions of git_access_tokens, in scan order. uuid[] and inet
// travel as text so no driver-specific codec is involved; nullable text becomes ” (COALESCE).
var gitTokenColumns = []string{
	"id", "user_id", "kind", "name", "token_hash", "prefix", "scope",
	"project_ids::text[]", "COALESCE(session_ref, '')", "COALESCE(host(created_ip), '')",
	"expires_at", "last_used_at", "COALESCE(host(last_used_ip), '')", "revoked_at",
	"COALESCE(revoked_reason, '')", "expiry_warned_at", "created_at",
}

var gitTokenCols = strings.Join(gitTokenColumns, ", ")

func scanGitToken(row interface{ Scan(...any) error }, t *gittokens.Token) error {
	var pids []string
	if err := row.Scan(
		&t.ID, &t.UserID, &t.Kind, &t.Name, &t.Hash, &t.Prefix, &t.Scope,
		&pids, &t.SessionRef, &t.CreatedIP,
		&t.ExpiresAt, &t.LastUsedAt, &t.LastUsedIP, &t.RevokedAt,
		&t.RevokedReason, &t.ExpiryWarnedAt, &t.CreatedAt,
	); err != nil {
		return err
	}
	t.ProjectIDs = t.ProjectIDs[:0]
	for _, s := range pids {
		id, err := uuid.Parse(s)
		if err != nil {
			return fmt.Errorf("parsing project id: %w", err)
		}
		t.ProjectIDs = append(t.ProjectIDs, id)
	}
	return nil
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

func (r *GitAccessRepository) CreateToken(ctx context.Context, t *gittokens.Token) (*gittokens.Token, error) {
	var out gittokens.Token
	err := scanGitToken(r.pool.QueryRow(ctx, `
		INSERT INTO git_access_tokens
			(user_id, kind, name, token_hash, prefix, scope, project_ids, session_ref, created_ip, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::uuid[], NULLIF($8, ''), NULLIF($9, '')::inet, $10)
		RETURNING `+gitTokenCols,
		t.UserID, t.Kind, t.Name, t.Hash, t.Prefix, t.Scope, uuidStrings(t.ProjectIDs), t.SessionRef, t.CreatedIP, t.ExpiresAt), &out)
	if err != nil {
		return nil, fmt.Errorf("creating git token: %w", err)
	}
	return &out, nil
}

func (r *GitAccessRepository) getOne(ctx context.Context, where string, arg any) (*gittokens.Token, error) {
	var t gittokens.Token
	err := scanGitToken(r.pool.QueryRow(ctx, `SELECT `+gitTokenCols+` FROM git_access_tokens WHERE `+where, arg), &t)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("loading git token: %w", err)
	}
	return &t, nil
}

func (r *GitAccessRepository) GetToken(ctx context.Context, id uuid.UUID) (*gittokens.Token, error) {
	return r.getOne(ctx, `id = $1`, id)
}

// GetTokenByHash returns the row even when revoked or expired: the caller decides and reports why.
func (r *GitAccessRepository) GetTokenByHash(ctx context.Context, hash string) (*gittokens.Token, error) {
	return r.getOne(ctx, `token_hash = $1`, hash)
}

func (r *GitAccessRepository) listTokens(ctx context.Context, q string, args ...any) ([]*gittokens.Token, error) {
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing git tokens: %w", err)
	}
	defer rows.Close()
	out := []*gittokens.Token{}
	for rows.Next() {
		var t gittokens.Token
		if err := scanGitToken(rows, &t); err != nil {
			return nil, fmt.Errorf("scanning git token: %w", err)
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

func (r *GitAccessRepository) ListUserTokens(ctx context.Context, userID uuid.UUID, now time.Time) ([]*gittokens.Token, error) {
	return r.listTokens(ctx, `SELECT `+gitTokenCols+` FROM git_access_tokens
		WHERE user_id = $1 AND kind IN ('personal', 'ephemeral') AND revoked_at IS NULL
		  AND (kind = 'personal' OR expires_at > $2)
		ORDER BY created_at DESC LIMIT 500`, userID, now)
}

func (r *GitAccessRepository) ListServiceTokens(ctx context.Context, projectID uuid.UUID, now time.Time) ([]*gittokens.Token, error) {
	return r.listTokens(ctx, `SELECT `+gitTokenCols+` FROM git_access_tokens
		WHERE kind = 'service' AND project_ids @> ARRAY[$1::uuid] AND revoked_at IS NULL
		ORDER BY created_at DESC LIMIT 200`, projectID)
}

func (r *GitAccessRepository) RevokeToken(ctx context.Context, id uuid.UUID, reason string) (bool, error) {
	tag, err := r.pool.Exec(ctx, `UPDATE git_access_tokens SET revoked_at = now(), revoked_reason = $2
		WHERE id = $1 AND revoked_at IS NULL`, id, reason)
	if err != nil {
		return false, fmt.Errorf("revoking git token: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func (r *GitAccessRepository) idsFrom(ctx context.Context, q string, args ...any) ([]uuid.UUID, error) {
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("revoking git tokens: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (r *GitAccessRepository) RevokeSession(ctx context.Context, userID uuid.UUID, sessionRef, reason string) ([]uuid.UUID, error) {
	return r.idsFrom(ctx, `UPDATE git_access_tokens SET revoked_at = now(), revoked_reason = $3
		WHERE user_id = $1 AND session_ref = $2 AND kind = 'ephemeral' AND revoked_at IS NULL
		RETURNING id`, userID, sessionRef, reason)
}

func (r *GitAccessRepository) PruneEphemeral(ctx context.Context, userID uuid.UUID, keep int, now time.Time) ([]uuid.UUID, error) {
	return r.idsFrom(ctx, `UPDATE git_access_tokens SET revoked_at = now(), revoked_reason = 'pruned'
		WHERE id IN (
			SELECT id FROM git_access_tokens
			WHERE user_id = $1 AND kind = 'ephemeral' AND revoked_at IS NULL AND expires_at > $3
			ORDER BY created_at DESC OFFSET $2)
		RETURNING id`, userID, keep, now)
}

func (r *GitAccessRepository) CountActive(ctx context.Context, userID uuid.UUID, kind string, now time.Time) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM git_access_tokens
		WHERE user_id = $1 AND kind = $2 AND revoked_at IS NULL AND expires_at > $3`, userID, kind, now).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("counting git tokens: %w", err)
	}
	return n, nil
}

// TouchUsed sets last_used_at/ip and reports whether the token had never been used. The row is
// locked first so two concurrent first requests cannot both see "never used".
func (r *GitAccessRepository) TouchUsed(ctx context.Context, id uuid.UUID, ip string) (bool, error) {
	var first bool
	err := r.pool.QueryRow(ctx, `
		WITH old AS (SELECT id, last_used_at FROM git_access_tokens WHERE id = $1 FOR UPDATE)
		UPDATE git_access_tokens t SET last_used_at = now(), last_used_ip = NULLIF($2, '')::inet
		FROM old WHERE t.id = old.id
		RETURNING old.last_used_at IS NULL`, id, ip).Scan(&first)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, domain.ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("recording git token use: %w", err)
	}
	return first, nil
}

func (r *GitAccessRepository) ListExpiring(ctx context.Context, from, to time.Time, limit int) ([]*gittokens.Token, error) {
	return r.listTokens(ctx, `SELECT `+gitTokenCols+` FROM git_access_tokens
		WHERE kind IN ('personal', 'service') AND revoked_at IS NULL AND expiry_warned_at IS NULL
		  AND expires_at > $1 AND expires_at <= $2
		ORDER BY expires_at LIMIT $3`, from, to, limit)
}

func (r *GitAccessRepository) MarkExpiryWarned(ctx context.Context, id uuid.UUID) error {
	if _, err := r.pool.Exec(ctx, `UPDATE git_access_tokens SET expiry_warned_at = now() WHERE id = $1`, id); err != nil {
		return fmt.Errorf("marking git token warned: %w", err)
	}
	return nil
}

func (r *GitAccessRepository) PurgeEphemeral(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM git_access_tokens
		WHERE kind = 'ephemeral' AND (expires_at < $1 OR revoked_at < $1)`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("purging git tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Audit writes one audit_logs row (org_id may be NULL).
func (r *GitAccessRepository) Audit(ctx context.Context, a gittokens.AuditRecord) error {
	meta := []byte("{}")
	if a.Meta != nil {
		b, err := json.Marshal(a.Meta)
		if err != nil {
			return fmt.Errorf("encoding audit metadata: %w", err)
		}
		meta = b
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO audit_logs (user_id, org_id, action, resource_type, resource_id, ip_address, metadata)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, '')::inet, $7::jsonb)`,
		a.UserID, a.OrgID, a.Action, a.ResourceType, a.ResourceID, a.IP, string(meta))
	if err != nil {
		return fmt.Errorf("writing audit log: %w", err)
	}
	return nil
}
