package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/kynto/capsule/backend/internal/authz/catalog"
	"github.com/kynto/capsule/backend/internal/authz/engine"
	"github.com/kynto/capsule/backend/internal/authz/systemtemplates"
	"github.com/kynto/capsule/backend/internal/repository"
)

// Actor is who performs a request and from where; it ends up in the audit row (never a secret).
type Actor struct {
	UserID    uuid.UUID
	IP        string
	UserAgent string
	RequestID string
	Via       string     // session | token
	TokenID   *uuid.UUID // set when Via == "token"
}

// Idem is the Idempotency-Key of a write request and the hash of the request it came with.
type Idem struct {
	Key  string
	Hash string
}

// HashRequest fingerprints a request for idempotency (method, path and raw body).
func HashRequest(method, path string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// Reply is the outcome of an idempotent write: Status is the HTTP status of the first execution; Replayed is true when the stored
// response of an earlier identical request was returned instead of executing again.
type Reply[T any] struct {
	Value    T
	Status   int
	Replayed bool
}

// querier is satisfied by *pgxpool.Pool and pgx.Tx.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Service implements the domain logic of the permission API.
type Service struct {
	store *repository.AccessStore
	eng   *engine.Engine
	log   *slog.Logger
	now   func() time.Time
	me    *meCache

	// failAudit lets tests make the audit write fail to prove the change rolls back with it.
	failAudit func(action string) error
}

// New returns a Service over the store and the engine of the process.
func New(store *repository.AccessStore, eng *engine.Engine, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: store, eng: eng, log: log, now: time.Now, me: newMeCache()}
}

func (s *Service) q() querier { return s.store.Pool() }

// ---------------------------------------------------------------- authorization

func needStrict(perms []string) bool {
	for _, p := range perms {
		if c, ok := catalog.Get(p); ok && c.Sensitive {
			return true
		}
	}
	return false
}

func (s *Service) effective(ctx context.Context, user, org uuid.UUID, sc engine.Scope, strict bool) (engine.Access, engine.Set, error) {
	if strict {
		return s.eng.EffectiveStrict(ctx, user, org, sc)
	}
	return s.eng.Effective(ctx, user, org, sc)
}

// require checks that the actor holds every perm at the scope and returns the set. Non-members get 403 "not a member"; a hidden
// project is the 404 of the scope; a visible scope without the permission gets the 403 PERMISSION_DENIED of SPEC 11.2 with the
// missing list.
func (s *Service) require(ctx context.Context, actor Actor, org uuid.UUID, sc engine.Scope, perms ...string) (engine.Set, error) {
	acc, set, err := s.effective(ctx, actor.UserID, org, sc, needStrict(perms))
	if err != nil {
		return engine.Set{}, err
	}
	if !acc.Member {
		return engine.Set{}, forbidden("not a member")
	}
	if acc.Hidden {
		return engine.Set{}, notFound("project not found")
	}
	var missing []string
	for _, p := range perms {
		if !set.Has(p) {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return set, nil
	}
	reason := "no_grant"
	if acc.Reason == engine.ReasonSuspended {
		reason = "suspended"
	} else if d, err := s.eng.Explain(ctx, actor.UserID, org, sc, missing[0]); err == nil && d.Cause == engine.CauseCeiling {
		reason = "ceiling"
	}
	return engine.Set{}, denied(perms[0], missing, reason)
}

// isOwner reports whether the actor currently holds the system "owner" organization template (the no-escalation exemption of
// SPEC 13.1: an active owner of an active account).
func (s *Service) isOwner(ctx context.Context, q querier, org, user uuid.UUID) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM org_members om JOIN users u ON u.id = om.user_id
		                WHERE om.org_id = $1 AND om.user_id = $2 AND om.status = 'active' AND u.status = 'active' AND om.template_id = $3)`,
		org, user, systemtemplates.ID(systemtemplates.KindOrg, "owner")).Scan(&ok)
	return ok, err
}

// projectCaps is what the actor is guaranteed to hold in EVERY project of the organization (the intersection of their effective sets;
// hidden projects count as empty). It is the capability a project or repo template edit is checked against: a template is applied
// in many projects, so an editor may only add what they hold everywhere. With no projects it falls back to the organization set.
func (s *Service) projectCaps(ctx context.Context, user, org uuid.UUID) (engine.Set, error) {
	ids, err := s.projectIDs(ctx, s.q(), org)
	if err != nil {
		return engine.Set{}, err
	}
	if len(ids) == 0 {
		_, set, err := s.eng.Effective(ctx, user, org, engine.OrgScope())
		return set, err
	}
	caps := catalog.Full()
	for _, id := range ids {
		_, set, err := s.eng.Effective(ctx, user, org, engine.ProjectScope(id))
		if err != nil {
			return engine.Set{}, err
		}
		caps = caps.Intersect(set)
		if caps.IsEmpty() {
			break
		}
	}
	return caps, nil
}

func (s *Service) projectIDs(ctx context.Context, q querier, org uuid.UUID) ([]uuid.UUID, error) {
	rows, err := q.Query(ctx, `SELECT id FROM projects WHERE org_id = $1 AND deleted_at IS NULL ORDER BY id`, org)
	if err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
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

// resolveScope validates a scope reference against the organization and returns the engine scope. A project, repo or environment of
// another organization or that does not exist is the same 404 ("project not found") as one the actor cannot see.
func (s *Service) resolveScope(ctx context.Context, q querier, org uuid.UUID, typ string, id uuid.UUID) (engine.Scope, uuid.UUID, error) {
	switch typ {
	case "org":
		if id != uuid.Nil && id != org {
			return engine.Scope{}, uuid.Nil, notFound("project not found")
		}
		return engine.OrgScope(), org, nil
	case "project", "repo":
		var ok bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL)`, id, org).Scan(&ok); err != nil {
			return engine.Scope{}, uuid.Nil, err
		}
		if !ok {
			return engine.Scope{}, id, notFound("project not found")
		}
		if typ == "repo" {
			return engine.RepoScope(id, id), id, nil // a repository is 1:1 with its project and shares its id
		}
		return engine.ProjectScope(id), id, nil
	case "env":
		var project uuid.UUID
		err := q.QueryRow(ctx, `SELECT e.project_id FROM environments e JOIN projects p ON p.id = e.project_id WHERE e.id = $1 AND p.org_id = $2 AND p.deleted_at IS NULL`, id, org).Scan(&project)
		if errors.Is(err, pgx.ErrNoRows) {
			return engine.Scope{}, uuid.Nil, notFound("project not found")
		}
		if err != nil {
			return engine.Scope{}, uuid.Nil, err
		}
		return engine.EnvScope(project, id), project, nil
	}
	return engine.Scope{}, uuid.Nil, validationField("scope.type", "must be org, project, repo or env")
}

// ---------------------------------------------------------------- writes: transaction, idempotency, audit

var errReplay = errors.New("idempotent replay")

// doWrite runs fn in the organization transaction (lock + epoch bump + NOTIFY, repository.AccessStore.InTx). With an Idempotency-Key the
// stored response of an identical earlier request is returned without running fn; the same key with another request is
// 409 IDEMPOTENCY_CONFLICT. The key row is written in the same transaction as the change. After the commit the local engine cache and
// the /me/permissions cache are flushed so the next read of this process already sees the change (SPEC 12.2).
func doWrite[T any](ctx context.Context, s *Service, org uuid.UUID, actor Actor, idem *Idem, status int, fn func(tx pgx.Tx) (T, error)) (Reply[T], error) {
	if idem != nil && (idem.Key == "" || len(idem.Key) > 128) {
		return Reply[T]{}, validationField("Idempotency-Key", "must be 1 to 128 characters")
	}
	var out T
	rstatus, replayed := status, false
	err := s.store.InTx(ctx, org, func(tx pgx.Tx) error {
		if idem != nil {
			if _, err := tx.Exec(ctx, `DELETE FROM access_idempotency WHERE org_id = $1 AND user_id = $2 AND key = $3 AND created_at <= now() - interval '24 hours'`,
				org, actor.UserID, idem.Key); err != nil {
				return err
			}
			var hash string
			var st int
			var resp []byte
			err := tx.QueryRow(ctx, `SELECT request_hash, status, response FROM access_idempotency WHERE org_id = $1 AND user_id = $2 AND key = $3`,
				org, actor.UserID, idem.Key).Scan(&hash, &st, &resp)
			if err == nil {
				if strings.TrimSpace(hash) != idem.Hash {
					return &Error{Status: 409, Code: "IDEMPOTENCY_CONFLICT", Message: "that Idempotency-Key was used with a different request"}
				}
				if len(resp) > 0 {
					if err := json.Unmarshal(resp, &out); err != nil {
						return fmt.Errorf("decoding stored response: %w", err)
					}
				}
				rstatus, replayed = st, true
				return errReplay
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		v, err := fn(tx)
		if err != nil {
			return err
		}
		out = v
		if idem != nil {
			b, err := json.Marshal(v)
			if err != nil {
				return fmt.Errorf("encoding response: %w", err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO access_idempotency (org_id, user_id, key, request_hash, status, response) VALUES ($1,$2,$3,$4,$5,$6::jsonb)`,
				org, actor.UserID, idem.Key, idem.Hash, status, string(b)); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, errReplay) {
		return Reply[T]{Value: out, Status: rstatus, Replayed: true}, nil
	}
	if err != nil {
		return Reply[T]{}, Normalize(err)
	}
	s.eng.Invalidate(engine.Target{Org: org})
	s.me.purgeOrg(org)
	return Reply[T]{Value: out, Status: rstatus, Replayed: replayed}, nil
}

type auditRow struct {
	Action       string
	ResourceType string // template | group | group_member | assignment | org_member | org_policy
	ResourceID   uuid.UUID
	ProjectID    *uuid.UUID
	Old, New     map[string]any
	Impact       int
	Extra        map[string]any // goes into metadata (no secrets)
}

// audit writes one audit_logs row inside tx. A failure fails the whole change.
func (s *Service) audit(ctx context.Context, tx pgx.Tx, org uuid.UUID, a Actor, r auditRow) error {
	if s.failAudit != nil {
		if err := s.failAudit(r.Action); err != nil {
			return err
		}
	}
	meta := map[string]any{"via": a.Via, "impact": r.Impact}
	if a.Via == "" {
		meta["via"] = "session"
	}
	if a.RequestID != "" {
		meta["request_id"] = a.RequestID
	}
	if a.TokenID != nil {
		meta["token_id"] = a.TokenID.String()
	}
	for k, v := range r.Extra {
		meta[k] = v
	}
	var oldArg, newArg any
	if r.Old != nil {
		b, err := json.Marshal(r.Old)
		if err != nil {
			return fmt.Errorf("encoding audit values: %w", err)
		}
		oldArg = string(b)
	}
	if r.New != nil {
		b, err := json.Marshal(r.New)
		if err != nil {
			return fmt.Errorf("encoding audit values: %w", err)
		}
		newArg = string(b)
	}
	metaV, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("encoding audit metadata: %w", err)
	}
	ip := ""
	if p, err := netip.ParseAddr(a.IP); err == nil {
		ip = p.String()
	}
	ua := a.UserAgent
	if len(ua) > 400 {
		ua = ua[:400]
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit_logs (id, user_id, org_id, project_id, actor_label, action, resource_type, resource_id,
			ip_address, user_agent, old_values, new_values, metadata, created_at)
		VALUES ($1, $2, $3, $4, '', $5, $6, $7, NULLIF($8, '')::inet, NULLIF($9, ''), $10::jsonb, $11::jsonb, $12::jsonb, $13)`,
		uuid.New(), a.UserID, org, r.ProjectID, r.Action, r.ResourceType, r.ResourceID, ip, ua, oldArg, newArg, string(metaV), s.now().UTC())
	if err != nil {
		return fmt.Errorf("writing audit log: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------- shared lookups

// UserRef is the public shape of a person.
type UserRef struct {
	ID    uuid.UUID `json:"id"`
	Email string    `json:"email"`
	Name  string    `json:"name"`
}

func (s *Service) userRefs(ctx context.Context, q querier, ids []uuid.UUID) (map[uuid.UUID]UserRef, error) {
	out := make(map[uuid.UUID]UserRef, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT id, email, name FROM users WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var u UserRef
		if err := rows.Scan(&u.ID, &u.Email, &u.Name); err != nil {
			return nil, err
		}
		out[u.ID] = u
	}
	return out, rows.Err()
}

type orgSettings struct {
	TempAccessMaxDays int  `json:"temp_access_max_days"`
	CustomRoles       bool `json:"custom_roles"`
}

func (s *Service) orgSettings(ctx context.Context, q querier, org uuid.UUID) (orgSettings, error) {
	var raw []byte
	if err := q.QueryRow(ctx, `SELECT access_settings FROM organizations WHERE id = $1`, org).Scan(&raw); err != nil {
		return orgSettings{}, err
	}
	st := orgSettings{TempAccessMaxDays: 90}
	_ = json.Unmarshal(raw, &st)
	if st.TempAccessMaxDays < 1 || st.TempAccessMaxDays > 365 {
		st.TempAccessMaxDays = 90
	}
	return st, nil
}

// checkExpiry validates an optional expiry: in the future and within the organization maximum (SPEC 8).
func (s *Service) checkExpiry(ctx context.Context, q querier, org uuid.UUID, field string, at *time.Time) error {
	if at == nil {
		return nil
	}
	now := s.now()
	if !at.After(now) {
		return validationField(field, "must be in the future")
	}
	st, err := s.orgSettings(ctx, q, org)
	if err != nil {
		return err
	}
	if at.After(now.Add(time.Duration(st.TempAccessMaxDays) * 24 * time.Hour)) {
		return validationField(field, fmt.Sprintf("exceeds the organization maximum of %d days", st.TempAccessMaxDays))
	}
	return nil
}
