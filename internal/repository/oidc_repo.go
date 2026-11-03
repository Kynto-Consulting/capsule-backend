package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/oidc"
)

// Column lists. Each must match its scan function (see oidc_repo_test.go).
const (
	oauthClientCols  = "id, client_id, secret_hash, name, redirect_uris, org_id, first_party, created_by, created_at, revoked_at"
	oauthRequestCols = "id, client_id, redirect_uri, scope, state, nonce, code_challenge, created_at, expires_at"
	oauthCodeCols    = "id, code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge, auth_time, expires_at, used_at, revoked_at, created_at"
	oauthRefreshCols = "id, token_hash, grant_id, client_id, user_id, scope, expires_at, used_at, revoked_at, created_at"
)

// oidcRowScanner is satisfied by pgx.Row and pgx.Rows.
type oidcRowScanner interface {
	Scan(dest ...any) error
}

func scanOAuthClient(row oidcRowScanner, c *oidc.Client) error {
	return row.Scan(&c.ID, &c.ClientID, &c.SecretHash, &c.Name, &c.RedirectURIs, &c.OrgID,
		&c.FirstParty, &c.CreatedBy, &c.CreatedAt, &c.RevokedAt)
}

func scanOAuthRequest(row oidcRowScanner, r *oidc.AuthRequest) error {
	return row.Scan(&r.ID, &r.ClientUUID, &r.RedirectURI, &r.Scope, &r.State, &r.Nonce,
		&r.CodeChallenge, &r.CreatedAt, &r.ExpiresAt)
}

func scanOAuthCode(row oidcRowScanner, c *oidc.Code) error {
	return row.Scan(&c.ID, &c.CodeHash, &c.ClientUUID, &c.UserID, &c.RedirectURI, &c.Scope, &c.Nonce,
		&c.CodeChallenge, &c.AuthTime, &c.ExpiresAt, &c.UsedAt, &c.RevokedAt, &c.CreatedAt)
}

func scanOAuthRefresh(row oidcRowScanner, t *oidc.RefreshToken) error {
	return row.Scan(&t.ID, &t.TokenHash, &t.GrantID, &t.ClientUUID, &t.UserID, &t.Scope,
		&t.ExpiresAt, &t.UsedAt, &t.RevokedAt, &t.CreatedAt)
}

// OIDCRepository implements oidc.Store on Postgres.
type OIDCRepository struct {
	pool *pgxpool.Pool
}

func NewOIDCRepository(pool *pgxpool.Pool) *OIDCRepository {
	return &OIDCRepository{pool: pool}
}

var _ oidc.Store = (*OIDCRepository)(nil)

func oidcNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}

// ---- clients ---------------------------------------------------------------

func (r *OIDCRepository) CreateClient(ctx context.Context, c *oidc.Client) error {
	uris := c.RedirectURIs
	if uris == nil {
		uris = []string{}
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_clients (id, client_id, secret_hash, name, redirect_uris, org_id, first_party, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.ID, c.ClientID, c.SecretHash, c.Name, uris, c.OrgID, c.FirstParty, c.CreatedBy, c.CreatedAt)
	return err
}

func (r *OIDCRepository) getClient(ctx context.Context, where string, arg any) (*oidc.Client, error) {
	var c oidc.Client
	err := scanOAuthClient(r.pool.QueryRow(ctx, `SELECT `+oauthClientCols+` FROM oauth_clients WHERE `+where, arg), &c)
	if err != nil {
		return nil, oidcNotFound(err)
	}
	return &c, nil
}

func (r *OIDCRepository) GetClientByClientID(ctx context.Context, clientID string) (*oidc.Client, error) {
	return r.getClient(ctx, "client_id = $1", clientID)
}

func (r *OIDCRepository) GetClientByUUID(ctx context.Context, id uuid.UUID) (*oidc.Client, error) {
	return r.getClient(ctx, "id = $1", id)
}

func (r *OIDCRepository) GetClient(ctx context.Context, ref string) (*oidc.Client, error) {
	return r.getClient(ctx, "(client_id = $1 OR id::text = $1)", ref)
}

func (r *OIDCRepository) ListClients(ctx context.Context, all bool, orgIDs []uuid.UUID) ([]*oidc.Client, error) {
	q := `SELECT ` + oauthClientCols + ` FROM oauth_clients`
	var args []any
	if !all {
		ids := make([]string, 0, len(orgIDs))
		for _, id := range orgIDs {
			ids = append(ids, id.String())
		}
		q += ` WHERE org_id::text = ANY($1)`
		args = append(args, ids)
	}
	q += ` ORDER BY created_at DESC`
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing oauth clients: %w", err)
	}
	defer rows.Close()
	out := []*oidc.Client{}
	for rows.Next() {
		var c oidc.Client
		if err := scanOAuthClient(rows, &c); err != nil {
			return nil, fmt.Errorf("scanning oauth client: %w", err)
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

func (r *OIDCRepository) UpdateRedirectURIs(ctx context.Context, id uuid.UUID, uris []string) error {
	if uris == nil {
		uris = []string{}
	}
	tag, err := r.pool.Exec(ctx, `UPDATE oauth_clients SET redirect_uris = $2 WHERE id = $1 AND revoked_at IS NULL`, id, uris)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *OIDCRepository) RevokeClient(ctx context.Context, id uuid.UUID) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `UPDATE oauth_clients SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE oauth_codes SET revoked_at = now() WHERE client_id = $1 AND revoked_at IS NULL`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE client_id = $1 AND revoked_at IS NULL`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---- pending requests ------------------------------------------------------

func (r *OIDCRepository) CreateRequest(ctx context.Context, q *oidc.AuthRequest) error {
	// Best-effort housekeeping on the (low-traffic) authorize path.
	_, _ = r.pool.Exec(ctx, `DELETE FROM oauth_requests WHERE expires_at < now()`)
	_, _ = r.pool.Exec(ctx, `DELETE FROM oauth_refresh_tokens WHERE expires_at < now() - interval '1 day'`)
	_, _ = r.pool.Exec(ctx, `
		DELETE FROM oauth_codes c
		WHERE c.expires_at < now() - interval '1 day'
		  AND NOT EXISTS (SELECT 1 FROM oauth_refresh_tokens t WHERE t.grant_id = c.id)`)

	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_requests (id, client_id, redirect_uri, scope, state, nonce, code_challenge, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		q.ID, q.ClientUUID, q.RedirectURI, q.Scope, q.State, q.Nonce, q.CodeChallenge, q.CreatedAt, q.ExpiresAt)
	return err
}

func (r *OIDCRepository) GetRequest(ctx context.Context, id string) (*oidc.AuthRequest, error) {
	var q oidc.AuthRequest
	err := scanOAuthRequest(r.pool.QueryRow(ctx,
		`SELECT `+oauthRequestCols+` FROM oauth_requests WHERE id = $1 AND expires_at > now()`, id), &q)
	if err != nil {
		return nil, oidcNotFound(err)
	}
	return &q, nil
}

func (r *OIDCRepository) TakeRequest(ctx context.Context, id string) (*oidc.AuthRequest, error) {
	var q oidc.AuthRequest
	err := scanOAuthRequest(r.pool.QueryRow(ctx,
		`DELETE FROM oauth_requests WHERE id = $1 AND expires_at > now() RETURNING `+oauthRequestCols, id), &q)
	if err != nil {
		return nil, oidcNotFound(err)
	}
	return &q, nil
}

// ---- codes / grants --------------------------------------------------------

func (r *OIDCRepository) CreateCode(ctx context.Context, c *oidc.Code) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_codes (id, code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge, auth_time, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		c.ID, c.CodeHash, c.ClientUUID, c.UserID, c.RedirectURI, c.Scope, c.Nonce, c.CodeChallenge,
		c.AuthTime, c.ExpiresAt, c.CreatedAt)
	return err
}

func (r *OIDCRepository) ConsumeCode(ctx context.Context, hash string) (*oidc.Code, bool, error) {
	var c oidc.Code
	err := scanOAuthCode(r.pool.QueryRow(ctx, `
		UPDATE oauth_codes SET used_at = now()
		WHERE code_hash = $1 AND used_at IS NULL AND revoked_at IS NULL
		RETURNING `+oauthCodeCols, hash), &c)
	if err == nil {
		return &c, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	// Not consumable now: either unknown or already used/revoked.
	err = scanOAuthCode(r.pool.QueryRow(ctx, `SELECT `+oauthCodeCols+` FROM oauth_codes WHERE code_hash = $1`, hash), &c)
	if err != nil {
		return nil, false, oidcNotFound(err)
	}
	return &c, false, nil
}

func (r *OIDCRepository) RevokeGrant(ctx context.Context, grantID uuid.UUID) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `UPDATE oauth_codes SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, grantID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE grant_id = $1 AND revoked_at IS NULL`, grantID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *OIDCRepository) GrantActive(ctx context.Context, grantID uuid.UUID) (bool, error) {
	var active bool
	err := r.pool.QueryRow(ctx, `SELECT revoked_at IS NULL FROM oauth_codes WHERE id = $1`, grantID).Scan(&active)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return active, nil
}

// ---- refresh tokens --------------------------------------------------------

func (r *OIDCRepository) CreateRefresh(ctx context.Context, t *oidc.RefreshToken) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_refresh_tokens (id, token_hash, grant_id, client_id, user_id, scope, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		t.ID, t.TokenHash, t.GrantID, t.ClientUUID, t.UserID, t.Scope, t.ExpiresAt, t.CreatedAt)
	return err
}

func (r *OIDCRepository) UseRefresh(ctx context.Context, hash string) (*oidc.RefreshToken, bool, error) {
	var t oidc.RefreshToken
	err := scanOAuthRefresh(r.pool.QueryRow(ctx, `
		UPDATE oauth_refresh_tokens SET used_at = now()
		WHERE token_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
		RETURNING `+oauthRefreshCols, hash), &t)
	if err == nil {
		return &t, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	err = scanOAuthRefresh(r.pool.QueryRow(ctx, `SELECT `+oauthRefreshCols+` FROM oauth_refresh_tokens WHERE token_hash = $1`, hash), &t)
	if err != nil {
		return nil, false, oidcNotFound(err)
	}
	return &t, false, nil
}

// ---- identity lookups ------------------------------------------------------

func (r *OIDCRepository) UserOrgs(ctx context.Context, userID uuid.UUID) ([]oidc.OrgRole, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT o.id, o.slug, m.role
		FROM org_members m
		JOIN organizations o ON o.id = m.org_id
		WHERE m.user_id = $1 AND o.deleted_at IS NULL
		ORDER BY o.slug`, userID)
	if err != nil {
		return nil, fmt.Errorf("listing user orgs: %w", err)
	}
	defer rows.Close()
	out := []oidc.OrgRole{}
	for rows.Next() {
		var o oidc.OrgRole
		if err := scanOrgRole(rows, &o); err != nil {
			return nil, fmt.Errorf("scanning org role: %w", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

const orgRoleCols = "o.id, o.slug, m.role"

func scanOrgRole(row oidcRowScanner, o *oidc.OrgRole) error {
	return row.Scan(&o.OrgID, &o.Slug, &o.Role)
}

// UsernameTaken mirrors oidc.SanitizeUsername in SQL: lower-case local part,
// [^a-z0-9._-] -> '-', first 32 chars, trim '-._', empty -> 'user'. An older
// user (created_at, id) with the same base owns it.
func (r *OIDCRepository) UsernameTaken(ctx context.Context, userID uuid.UUID, base string) (bool, error) {
	var taken bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM users u, users me
			WHERE me.id = $1
			  AND u.id <> me.id
			  AND u.deleted_at IS NULL
			  AND COALESCE(NULLIF(btrim(left(regexp_replace(lower(split_part(u.email, '@', 1)), '[^a-z0-9._-]', '-', 'g'), 32), '-._'), ''), 'user') = $2
			  AND (u.created_at, u.id) < (me.created_at, me.id)
		)`, userID, base).Scan(&taken)
	return taken, err
}
