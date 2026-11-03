//go:build dbtest

package repository

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gittokens"
)

// Needs TEST_DATABASE_URL (see dbtest_helpers_db_test.go). Covers migrations 000044-000045.

type gitAccessFx struct {
	t    *testing.T
	repo *GitAccessRepository
	user uuid.UUID
	org  uuid.UUID
	proj uuid.UUID
}

func newGitAccessFx(t *testing.T) *gitAccessFx {
	t.Helper()
	pool := sharedPool(t)
	f := newFx(t, pool)
	u := f.user("", time.Now())
	o := f.org(u)
	return &gitAccessFx{t: t, repo: NewGitAccessRepository(pool), user: u, org: o, proj: f.project(o, "")}
}

func (g *gitAccessFx) token(kind, scope string, projects []uuid.UUID, session string, expires time.Time) *gittokens.Token {
	g.t.Helper()
	plain, hash, err := gittokens.Generate(nil)
	if err != nil {
		g.t.Fatal(err)
	}
	tok, err := g.repo.CreateToken(context.Background(), &gittokens.Token{
		UserID: g.user, Kind: kind, Name: "n", Hash: hash, Prefix: gittokens.DisplayPrefix(plain), Scope: scope,
		ProjectIDs: projects, SessionRef: session, CreatedIP: "203.0.113.5", ExpiresAt: expires,
	})
	if err != nil {
		g.t.Fatalf("create token: %v", err)
	}
	return tok
}

func TestGitTokenRoundTrip(t *testing.T) {
	g := newGitAccessFx(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	tok := g.token(gittokens.KindEphemeral, "write", []uuid.UUID{g.proj}, "cli:abcdefghijklmnop", exp)

	got, err := g.repo.GetTokenByHash(ctx, tok.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != tok.ID || got.UserID != g.user || got.Kind != "ephemeral" || got.Scope != "write" || got.SessionRef != "cli:abcdefghijklmnop" ||
		got.CreatedIP != "203.0.113.5" || len(got.ProjectIDs) != 1 || got.ProjectIDs[0] != g.proj || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if got.RevokedAt != nil || got.LastUsedAt != nil {
		t.Fatal("fresh token has no revocation or use")
	}
	if _, err := g.repo.GetTokenByHash(ctx, gittokens.Hash("nope")); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown hash must be ErrNotFound, got %v", err)
	}
	if _, err := g.repo.GetToken(ctx, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("unknown id must be ErrNotFound")
	}

	// Personal tokens may have no project list; NULLIF keeps session_ref NULL, read back as "".
	p := g.token(gittokens.KindPersonal, "read", nil, "", exp)
	if pg, _ := g.repo.GetToken(ctx, p.ID); len(pg.ProjectIDs) != 0 || pg.SessionRef != "" {
		t.Fatalf("%+v", pg)
	}
}

// The value of a token must not be recoverable from any column of the table.
func TestGitTokenValueIsNeverStored(t *testing.T) {
	g := newGitAccessFx(t)
	ctx := context.Background()
	plain, hash, _ := gittokens.Generate(nil)
	tok, err := g.repo.CreateToken(ctx, &gittokens.Token{UserID: g.user, Kind: "personal", Name: "n", Hash: hash, Prefix: gittokens.DisplayPrefix(plain), Scope: "read", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var row string
	if err := g.repo.pool.QueryRow(ctx, `SELECT t::text FROM git_access_tokens t WHERE id = $1`, tok.ID).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row, plain) {
		t.Fatal("the token value is present in the stored row")
	}
	if !strings.Contains(row, hash) {
		t.Fatal("the hash must be stored")
	}
	// Same hash twice is refused (unique constraint).
	if _, err := g.repo.CreateToken(ctx, &gittokens.Token{UserID: g.user, Kind: "personal", Name: "n", Hash: hash, Prefix: "cgt_xxxx", Scope: "read", ExpiresAt: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("duplicate hash must fail")
	}
}

func TestGitTokenConstraints(t *testing.T) {
	g := newGitAccessFx(t)
	ctx := context.Background()
	mk := func(kind, scope string) error {
		_, h, _ := gittokens.Generate(nil)
		_, err := g.repo.CreateToken(ctx, &gittokens.Token{UserID: g.user, Kind: kind, Name: "n", Hash: h, Prefix: "cgt_xxxx", Scope: scope, ExpiresAt: time.Now().Add(time.Hour)})
		return err
	}
	if mk("bogus", "read") == nil || mk("personal", "admin") == nil {
		t.Fatal("kind and scope are constrained")
	}
}

func TestListUserAndServiceTokens(t *testing.T) {
	g := newGitAccessFx(t)
	ctx := context.Background()
	now := time.Now()
	live := g.token("personal", "read", nil, "", now.Add(time.Hour))
	expiredPersonal := g.token("personal", "read", nil, "", now.Add(-time.Hour)) // still listed so the user sees it
	eph := g.token("ephemeral", "write", []uuid.UUID{g.proj}, "cli:s1", now.Add(time.Hour))
	ephExpired := g.token("ephemeral", "write", []uuid.UUID{g.proj}, "cli:s1", now.Add(-time.Hour))
	revoked := g.token("personal", "read", nil, "", now.Add(time.Hour))
	if ok, err := g.repo.RevokeToken(ctx, revoked.ID, "user"); err != nil || !ok {
		t.Fatal("revoke")
	}
	svc := g.token("service", "write", []uuid.UUID{g.proj}, "", now.Add(24*time.Hour))
	otherProj := newFx(t, g.repo.pool).project(g.org, "")
	_ = g.token("service", "write", []uuid.UUID{otherProj}, "", now.Add(24*time.Hour))

	list, err := g.repo.ListUserTokens(ctx, g.user, now)
	if err != nil {
		t.Fatal(err)
	}
	have := map[uuid.UUID]bool{}
	for _, tk := range list {
		have[tk.ID] = true
	}
	for id, want := range map[uuid.UUID]bool{live.ID: true, expiredPersonal.ID: true, eph.ID: true, ephExpired.ID: false, revoked.ID: false, svc.ID: false} {
		if have[id] != want {
			t.Errorf("token %s listed=%v want %v", id, have[id], want)
		}
	}
	sl, err := g.repo.ListServiceTokens(ctx, g.proj, now)
	if err != nil || len(sl) != 1 || sl[0].ID != svc.ID {
		t.Fatalf("service tokens of the repo: %v %d", err, len(sl))
	}
}

func TestRevokeTokenAndSession(t *testing.T) {
	g := newGitAccessFx(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	a := g.token("ephemeral", "read", []uuid.UUID{g.proj}, "cli:s1", exp)
	b := g.token("ephemeral", "read", []uuid.UUID{g.proj}, "cli:s1", exp)
	c := g.token("ephemeral", "read", []uuid.UUID{g.proj}, "cli:s2", exp)
	p := g.token("personal", "read", nil, "", exp)

	ids, err := g.repo.RevokeSession(ctx, g.user, "cli:s1", "session")
	if err != nil || len(ids) != 2 {
		t.Fatalf("session revoke: %v %v", err, ids)
	}
	for _, id := range []uuid.UUID{a.ID, b.ID} {
		tk, _ := g.repo.GetToken(ctx, id)
		if tk.RevokedAt == nil || tk.RevokedReason != "session" {
			t.Fatal("not revoked")
		}
	}
	if tk, _ := g.repo.GetToken(ctx, c.ID); tk.RevokedAt != nil {
		t.Fatal("other session must survive")
	}
	if ids, _ := g.repo.RevokeSession(ctx, uuid.New(), "cli:s2", "x"); len(ids) != 0 {
		t.Fatal("another user's session is not touched")
	}
	if ok, _ := g.repo.RevokeToken(ctx, p.ID, "user"); !ok {
		t.Fatal("revoke personal")
	}
	if ok, _ := g.repo.RevokeToken(ctx, p.ID, "user"); ok {
		t.Fatal("revoking twice changes nothing")
	}
}

func TestPruneCountTouchExpiringPurge(t *testing.T) {
	g := newGitAccessFx(t)
	ctx := context.Background()
	now := time.Now()
	var eph []*gittokens.Token
	for i := 0; i < 4; i++ {
		eph = append(eph, g.token("ephemeral", "read", []uuid.UUID{g.proj}, "cli:s1", now.Add(time.Hour)))
		time.Sleep(5 * time.Millisecond)
	}
	if n, _ := g.repo.CountActive(ctx, g.user, "ephemeral", now); n != 4 {
		t.Fatalf("count %d", n)
	}
	ids, err := g.repo.PruneEphemeral(ctx, g.user, 2, now)
	if err != nil || len(ids) != 2 {
		t.Fatalf("prune: %v %v", err, ids)
	}
	for _, old := range eph[:2] { // the two oldest go
		if tk, _ := g.repo.GetToken(ctx, old.ID); tk.RevokedAt == nil {
			t.Fatal("the oldest tokens must be pruned")
		}
	}

	first, err := g.repo.TouchUsed(ctx, eph[3].ID, "198.51.100.1")
	if err != nil || !first {
		t.Fatalf("first touch: %v %v", err, first)
	}
	if first, _ = g.repo.TouchUsed(ctx, eph[3].ID, "198.51.100.2"); first {
		t.Fatal("second touch is not the first")
	}
	if tk, _ := g.repo.GetToken(ctx, eph[3].ID); tk.LastUsedAt == nil || tk.LastUsedIP != "198.51.100.2" {
		t.Fatalf("%+v", tk)
	}
	if _, err := g.repo.TouchUsed(ctx, uuid.New(), ""); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("touching an unknown token is ErrNotFound")
	}

	soon := g.token("personal", "read", nil, "", now.Add(3*24*time.Hour))
	_ = g.token("personal", "read", nil, "", now.Add(60*24*time.Hour))
	exp, err := g.repo.ListExpiring(ctx, now, now.Add(7*24*time.Hour), 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tk := range exp {
		if tk.ID == soon.ID {
			found = true
		}
		if tk.Kind == "ephemeral" {
			t.Fatal("ephemeral tokens are never warned about")
		}
	}
	if !found {
		t.Fatal("token expiring in 3 days must be listed")
	}
	if err := g.repo.MarkExpiryWarned(ctx, soon.ID); err != nil {
		t.Fatal(err)
	}
	exp, _ = g.repo.ListExpiring(ctx, now, now.Add(7*24*time.Hour), 50)
	for _, tk := range exp {
		if tk.ID == soon.ID {
			t.Fatal("warned tokens are not listed again")
		}
	}

	old := g.token("ephemeral", "read", []uuid.UUID{g.proj}, "cli:old", now.Add(-10*24*time.Hour))
	n, err := g.repo.PurgeEphemeral(ctx, now.Add(-7*24*time.Hour))
	if err != nil || n < 1 {
		t.Fatalf("purge: %v %d", err, n)
	}
	if _, err := g.repo.GetToken(ctx, old.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("old ephemeral token must be gone")
	}
	if _, err := g.repo.GetToken(ctx, soon.ID); err != nil {
		t.Fatal("personal tokens are never purged")
	}
}

func TestGitTokenCascadesWithUser(t *testing.T) {
	g := newGitAccessFx(t)
	ctx := context.Background()
	u2 := newFx(t, g.repo.pool).user("", time.Now())
	_, h, _ := gittokens.Generate(nil)
	tk, err := g.repo.CreateToken(ctx, &gittokens.Token{UserID: u2, Kind: "personal", Name: "n", Hash: h, Prefix: "cgt_xxxx", Scope: "read", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.repo.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, u2); err != nil {
		t.Fatal(err)
	}
	if _, err := g.repo.GetToken(ctx, tk.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("tokens go with their user")
	}
}

func TestGitAuditWithAndWithoutOrg(t *testing.T) {
	g := newGitAccessFx(t)
	ctx := context.Background()
	res := uuid.New()
	if err := g.repo.Audit(ctx, gittokens.AuditRecord{UserID: g.user, Action: "git_token.create", ResourceType: "git_token", ResourceID: res, IP: "203.0.113.9", Meta: map[string]any{"scope": "read"}}); err != nil {
		t.Fatalf("account-level audit (no org) must work: %v", err)
	}
	if err := g.repo.Audit(ctx, gittokens.AuditRecord{UserID: g.user, OrgID: &g.org, Action: "git_token.issue", ResourceType: "git_token", ResourceID: res}); err != nil {
		t.Fatalf("audit with org and no ip: %v", err)
	}
	var n int
	var ip, meta string
	if err := g.repo.pool.QueryRow(ctx, `SELECT count(*), max(host(ip_address)), string_agg(metadata::text, ' ' ORDER BY metadata::text) FROM audit_logs WHERE resource_id = $1`, res).Scan(&n, &ip, &meta); err != nil {
		t.Fatal(err)
	}
	if n != 2 || ip != "203.0.113.9" || !strings.Contains(meta, `"scope": "read"`) {
		t.Fatalf("n=%d ip=%q meta=%q", n, ip, meta)
	}
}

// ---- ssh keys ----

func (g *gitAccessFx) key(fp string) *gittokens.SSHKey {
	g.t.Helper()
	k, err := g.repo.CreateKey(context.Background(), &gittokens.SSHKey{UserID: g.user, Title: "t", PublicKey: "ssh-ed25519 AAAA" + fp, KeyType: "ssh-ed25519", Fingerprint: fp, NextSyncAt: time.Now().Add(-time.Minute)})
	if err != nil {
		g.t.Fatalf("create key: %v", err)
	}
	return k
}

func TestGitSSHKeyLifecycle(t *testing.T) {
	g := newGitAccessFx(t)
	ctx := context.Background()
	fp := "SHA256:" + uuid.NewString()
	k := g.key(fp)
	if k.ForgejoSynced() || k.SyncAttempts != 0 || k.DeletedAt != nil {
		t.Fatalf("%+v", k)
	}
	// One live registration per fingerprint, across users.
	other := newFx(t, g.repo.pool).user("", time.Now())
	_, err := g.repo.CreateKey(ctx, &gittokens.SSHKey{UserID: other, Title: "t", PublicKey: "x", KeyType: "ssh-ed25519", Fingerprint: fp, NextSyncAt: time.Now()})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate fingerprint must be ErrConflict, got %v", err)
	}

	pending, _ := g.repo.ListPendingKeys(ctx, time.Now(), 100)
	if !hasKey(pending, k.ID) {
		t.Fatal("an unsynced live key is pending")
	}
	if err := g.repo.MarkKeySyncFailed(ctx, k.ID, "boom", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if pending, _ = g.repo.ListPendingKeys(ctx, time.Now(), 100); hasKey(pending, k.ID) {
		t.Fatal("backoff: not due yet")
	}
	if got, _ := g.repo.GetKey(ctx, k.ID); got.SyncAttempts != 1 || got.SyncError != "boom" {
		t.Fatalf("%+v", got)
	}
	if err := g.repo.MarkKeySynced(ctx, k.ID, 42); err != nil {
		t.Fatal(err)
	}
	got, _ := g.repo.GetKey(ctx, k.ID)
	if !got.ForgejoSynced() || *got.ForgejoKeyID != 42 || got.SyncError != "" || got.SyncAttempts != 0 {
		t.Fatalf("%+v", got)
	}
	if pending, _ = g.repo.ListPendingKeys(ctx, time.Now(), 100); hasKey(pending, k.ID) {
		t.Fatal("a synced key is not pending")
	}

	// Soft delete: gone from the list, pending removal from Forgejo, fingerprint reusable.
	if err := g.repo.SoftDeleteKey(ctx, k.ID, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := g.repo.SoftDeleteKey(ctx, k.ID, time.Now()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("deleting twice is ErrNotFound")
	}
	if l, _ := g.repo.ListKeys(ctx, g.user); hasKey(l, k.ID) {
		t.Fatal("deleted keys are not listed")
	}
	if pending, _ = g.repo.ListPendingKeys(ctx, time.Now(), 100); !hasKey(pending, k.ID) {
		t.Fatal("a deleted key still registered in Forgejo is pending removal")
	}
	if err := g.repo.MarkKeyRemoved(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	if pending, _ = g.repo.ListPendingKeys(ctx, time.Now(), 100); hasKey(pending, k.ID) {
		t.Fatal("removed key is done")
	}
	if _, err := g.repo.CreateKey(ctx, &gittokens.SSHKey{UserID: other, Title: "t", PublicKey: "x", KeyType: "ssh-ed25519", Fingerprint: fp, NextSyncAt: time.Now()}); err != nil {
		t.Fatalf("a deleted key's fingerprint can be registered again: %v", err)
	}
	// Deleted and never synced: nothing to do in Forgejo.
	k2 := g.key("SHA256:" + uuid.NewString())
	_ = g.repo.SoftDeleteKey(ctx, k2.ID, time.Now().Add(-time.Second))
	if pending, _ = g.repo.ListPendingKeys(ctx, time.Now(), 100); hasKey(pending, k2.ID) {
		t.Fatal("a never-synced deleted key is not pending")
	}
	if _, err := g.repo.GetKey(ctx, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("ErrNotFound")
	}
}

func hasKey(l []*gittokens.SSHKey, id uuid.UUID) bool {
	for _, k := range l {
		if k.ID == id {
			return true
		}
	}
	return false
}
