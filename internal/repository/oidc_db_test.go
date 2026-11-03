//go:build dbtest

package repository

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/oidc"
)

func oidcSetup(t *testing.T) (*OIDCRepository, *fx, uuid.UUID, uuid.UUID) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	u := f.user("", time.Now().Add(-time.Hour))
	org := f.org(u)
	f.member(org, u, "owner")
	return NewOIDCRepository(pool), f, u, org
}

func mkClient(t *testing.T, r *OIDCRepository, org, by *uuid.UUID, uris []string) *oidc.Client {
	t.Helper()
	c := &oidc.Client{ID: uuid.New(), ClientID: "cid-" + uuid.NewString(), SecretHash: "h", Name: "App",
		RedirectURIs: uris, OrgID: org, CreatedBy: by, CreatedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if err := r.CreateClient(context.Background(), c); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	return c
}

func TestOIDCClientsDB(t *testing.T) {
	r, _, u, org := oidcSetup(t)
	ctx := context.Background()

	c := mkClient(t, r, &org, &u, []string{"https://a/cb", "https://b/cb"})
	got, err := r.GetClientByClientID(ctx, c.ClientID)
	if err != nil || got.ID != c.ID || len(got.RedirectURIs) != 2 || got.OrgID == nil || *got.OrgID != org || got.RevokedAt != nil {
		t.Fatalf("GetClientByClientID: %+v %v", got, err)
	}
	if g, err := r.GetClientByUUID(ctx, c.ID); err != nil || g.ClientID != c.ClientID {
		t.Fatalf("GetClientByUUID: %v", err)
	}
	// GetClient resolves both the uuid text and the client_id
	if g, err := r.GetClient(ctx, c.ID.String()); err != nil || g.ID != c.ID {
		t.Fatalf("GetClient(uuid): %v", err)
	}
	if g, err := r.GetClient(ctx, c.ClientID); err != nil || g.ID != c.ID {
		t.Fatalf("GetClient(client_id): %v", err)
	}
	if _, err := r.GetClient(ctx, "nope-"+uuid.NewString()); err != domain.ErrNotFound {
		t.Fatalf("GetClient missing: %v", err)
	}
	if _, err := r.GetClientByUUID(ctx, uuid.New()); err != domain.ErrNotFound {
		t.Fatalf("GetClientByUUID missing: %v", err)
	}

	// nil redirect URIs / nil org / nil creator (first-party style)
	fp := &oidc.Client{ID: uuid.New(), ClientID: "fp-" + uuid.NewString(), Name: "FP", FirstParty: true, CreatedAt: time.Now()}
	if err := r.CreateClient(ctx, fp); err != nil {
		t.Fatalf("CreateClient first party: %v", err)
	}
	g, err := r.GetClientByUUID(ctx, fp.ID)
	if err != nil || !g.FirstParty || g.OrgID != nil || g.CreatedBy != nil || g.RedirectURIs == nil || len(g.RedirectURIs) != 0 || !g.Public() {
		t.Fatalf("first party: %+v %v", g, err)
	}
	// duplicate client_id
	dup := &oidc.Client{ID: uuid.New(), ClientID: c.ClientID, Name: "d", CreatedAt: time.Now()}
	if err := r.CreateClient(ctx, dup); err == nil {
		t.Fatal("duplicate client_id accepted")
	}

	// ListClients: owned by org vs all
	other := mkClient(t, r, nil, nil, nil)
	owned, err := r.ListClients(ctx, false, []uuid.UUID{org})
	if err != nil || len(owned) != 1 || owned[0].ID != c.ID {
		t.Fatalf("ListClients(org): %d %v", len(owned), err)
	}
	if none, err := r.ListClients(ctx, false, nil); err != nil || len(none) != 0 {
		t.Fatalf("ListClients(empty org list): %d %v", len(none), err)
	}
	all, err := r.ListClients(ctx, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uuid.UUID]bool{}
	for _, x := range all {
		seen[x.ID] = true
	}
	if !seen[c.ID] || !seen[other.ID] || !seen[fp.ID] {
		t.Fatalf("ListClients(all) missing rows")
	}

	// UpdateRedirectURIs
	if err := r.UpdateRedirectURIs(ctx, c.ID, []string{"https://z/cb"}); err != nil {
		t.Fatal(err)
	}
	g, _ = r.GetClientByUUID(ctx, c.ID)
	if len(g.RedirectURIs) != 1 || g.RedirectURIs[0] != "https://z/cb" {
		t.Fatalf("uris %v", g.RedirectURIs)
	}
	if err := r.UpdateRedirectURIs(ctx, c.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateRedirectURIs(ctx, uuid.New(), nil); err != domain.ErrNotFound {
		t.Fatalf("update missing: %v", err)
	}

	// RevokeClient revokes client + codes + refresh tokens
	code := mkCode(t, r, c.ID, u, "rev-"+uuid.NewString(), time.Hour)
	rt := mkRefresh(t, r, code, "rrev-"+uuid.NewString(), time.Hour)
	if err := r.RevokeClient(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	g, _ = r.GetClientByUUID(ctx, c.ID)
	if g.RevokedAt == nil {
		t.Fatal("client not revoked")
	}
	if err := r.RevokeClient(ctx, c.ID); err != domain.ErrNotFound {
		t.Fatalf("second revoke: %v", err)
	}
	if err := r.UpdateRedirectURIs(ctx, c.ID, []string{"x"}); err != domain.ErrNotFound {
		t.Fatalf("update revoked: %v", err)
	}
	if _, ok, err := r.ConsumeCode(ctx, code.CodeHash); err != nil || ok {
		t.Fatalf("revoked code consumable: ok=%v err=%v", ok, err)
	}
	if tok, ok, err := r.UseRefresh(ctx, rt.TokenHash); err != nil || ok || tok.RevokedAt == nil {
		t.Fatalf("revoked refresh usable: ok=%v err=%v", ok, err)
	}
	if act, err := r.GrantActive(ctx, code.ID); err != nil || act {
		t.Fatalf("grant active after revoke: %v %v", act, err)
	}
}

func TestOIDCRequestsDB(t *testing.T) {
	r, _, u, org := oidcSetup(t)
	ctx := context.Background()
	c := mkClient(t, r, &org, &u, []string{"https://a/cb"})

	mk := func(id string, exp time.Duration) *oidc.AuthRequest {
		return &oidc.AuthRequest{ID: id, ClientUUID: c.ID, RedirectURI: "https://a/cb", Scope: "openid", State: "s", Nonce: "n",
			CodeChallenge: "cc", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(exp).UTC()}
	}
	id1 := "req-" + uuid.NewString()
	if err := r.CreateRequest(ctx, mk(id1, time.Minute)); err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	g, err := r.GetRequest(ctx, id1)
	if err != nil || g.ClientUUID != c.ID || g.Scope != "openid" || g.CodeChallenge != "cc" {
		t.Fatalf("GetRequest: %+v %v", g, err)
	}
	// expired request is invisible and is cleaned by the next CreateRequest
	idx := "req-" + uuid.NewString()
	if err := r.CreateRequest(ctx, mk(idx, -time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.GetRequest(ctx, idx); err != domain.ErrNotFound {
		t.Fatalf("expired GetRequest: %v", err)
	}
	if _, err := r.TakeRequest(ctx, idx); err != domain.ErrNotFound {
		t.Fatalf("expired TakeRequest: %v", err)
	}
	id2 := "req-" + uuid.NewString()
	if err := r.CreateRequest(ctx, mk(id2, time.Minute)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM oauth_requests WHERE id=$1`, idx).Scan(&n); err != nil || n != 0 {
		t.Fatalf("expired request not cleaned: n=%d err=%v", n, err)
	}
	// TakeRequest is single-use, also under concurrency
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.TakeRequest(ctx, id1); err == nil {
				atomic.AddInt32(&wins, 1)
			} else if !errors.Is(err, domain.ErrNotFound) {
				t.Errorf("TakeRequest: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("TakeRequest winners = %d, want 1", wins)
	}
	if _, err := r.GetRequest(ctx, id1); err != domain.ErrNotFound {
		t.Fatalf("taken request still readable: %v", err)
	}
	// deleting the client cascades to requests
	if _, err := r.pool.Exec(ctx, `DELETE FROM oauth_clients WHERE id=$1`, c.ID); err != nil {
		t.Fatalf("delete client cascade: %v", err)
	}
	if _, err := r.GetRequest(ctx, id2); err != domain.ErrNotFound {
		t.Fatalf("request survived client delete: %v", err)
	}
}

func mkCode(t *testing.T, r *OIDCRepository, client, user uuid.UUID, hash string, ttl time.Duration) *oidc.Code {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	c := &oidc.Code{ID: uuid.New(), CodeHash: hash, ClientUUID: client, UserID: user, RedirectURI: "https://a/cb",
		Scope: "openid email", Nonce: "n", CodeChallenge: "ch", AuthTime: now, ExpiresAt: now.Add(ttl), CreatedAt: now}
	if err := r.CreateCode(context.Background(), c); err != nil {
		t.Fatalf("CreateCode: %v", err)
	}
	return c
}

func mkRefresh(t *testing.T, r *OIDCRepository, code *oidc.Code, hash string, ttl time.Duration) *oidc.RefreshToken {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	tok := &oidc.RefreshToken{ID: uuid.New(), TokenHash: hash, GrantID: code.ID, ClientUUID: code.ClientUUID, UserID: code.UserID,
		Scope: code.Scope, ExpiresAt: now.Add(ttl), CreatedAt: now}
	if err := r.CreateRefresh(context.Background(), tok); err != nil {
		t.Fatalf("CreateRefresh: %v", err)
	}
	return tok
}

func TestOIDCCodesAndRefreshDB(t *testing.T) {
	r, _, u, org := oidcSetup(t)
	ctx := context.Background()
	c := mkClient(t, r, &org, &u, []string{"https://a/cb"})

	// ---- consume once, then see it as already used ----
	h := "code-" + uuid.NewString()
	code := mkCode(t, r, c.ID, u, h, time.Minute)
	got, ok, err := r.ConsumeCode(ctx, h)
	if err != nil || !ok || got.ID != code.ID || got.UsedAt == nil || got.Scope != "openid email" ||
		got.Nonce != "n" || got.CodeChallenge != "ch" || got.RedirectURI != "https://a/cb" || got.UserID != u {
		t.Fatalf("first consume: %+v ok=%v err=%v", got, ok, err)
	}
	got2, ok, err := r.ConsumeCode(ctx, h)
	if err != nil || ok || got2.ID != code.ID || got2.UsedAt == nil {
		t.Fatalf("second consume: %+v ok=%v err=%v", got2, ok, err)
	}
	if _, _, err := r.ConsumeCode(ctx, "unknown-"+uuid.NewString()); err != domain.ErrNotFound {
		t.Fatalf("unknown code: %v", err)
	}
	// duplicate code hash rejected
	if err := r.CreateCode(ctx, &oidc.Code{ID: uuid.New(), CodeHash: h, ClientUUID: c.ID, UserID: u, RedirectURI: "x", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(), AuthTime: time.Now()}); err == nil {
		t.Fatal("duplicate code_hash accepted")
	}

	// ---- concurrency: one OAuth code, many goroutines, exactly one wins ----
	for round := 0; round < 3; round++ {
		hc := "race-" + uuid.NewString()
		mkCode(t, r, c.ID, u, hc, time.Minute)
		var wins int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, ok, err := r.ConsumeCode(ctx, hc)
				if err != nil {
					t.Errorf("ConsumeCode race: %v", err)
					return
				}
				if ok {
					atomic.AddInt32(&wins, 1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins != 1 {
			t.Fatalf("round %d: code consumed by %d goroutines, want exactly 1", round, wins)
		}
	}

	// ---- refresh: rotation + reuse detection ----
	grant := mkCode(t, r, c.ID, u, "g-"+uuid.NewString(), time.Minute)
	if act, err := r.GrantActive(ctx, grant.ID); err != nil || !act {
		t.Fatalf("GrantActive: %v %v", act, err)
	}
	if act, err := r.GrantActive(ctx, uuid.New()); err != nil || act {
		t.Fatalf("GrantActive unknown: %v %v", act, err)
	}
	r1 := mkRefresh(t, r, grant, "rt1-"+uuid.NewString(), time.Hour)
	used, ok, err := r.UseRefresh(ctx, r1.TokenHash)
	if err != nil || !ok || used.UsedAt == nil || used.GrantID != grant.ID || used.Scope != grant.Scope {
		t.Fatalf("UseRefresh first: %+v ok=%v err=%v", used, ok, err)
	}
	r2 := mkRefresh(t, r, grant, "rt2-"+uuid.NewString(), time.Hour) // rotation: successor
	replay, ok, err := r.UseRefresh(ctx, r1.TokenHash)               // reuse of the old one
	if err != nil || ok || replay.UsedAt == nil || replay.GrantID != grant.ID {
		t.Fatalf("UseRefresh replay: %+v ok=%v err=%v", replay, ok, err)
	}
	// reuse detected -> service revokes the grant -> successor dies too
	if err := r.RevokeGrant(ctx, replay.GrantID); err != nil {
		t.Fatal(err)
	}
	if act, _ := r.GrantActive(ctx, grant.ID); act {
		t.Fatal("grant still active after RevokeGrant")
	}
	if tok, ok, err := r.UseRefresh(ctx, r2.TokenHash); err != nil || ok || tok.RevokedAt == nil {
		t.Fatalf("successor usable after grant revoke: ok=%v err=%v", ok, err)
	}
	if _, _, err := r.UseRefresh(ctx, "none-"+uuid.NewString()); err != domain.ErrNotFound {
		t.Fatalf("unknown refresh: %v", err)
	}
	// expired refresh is not usable but is found
	rex := mkRefresh(t, r, mkCode(t, r, c.ID, u, "gx-"+uuid.NewString(), time.Minute), "rtx-"+uuid.NewString(), -time.Minute)
	if tok, ok, err := r.UseRefresh(ctx, rex.TokenHash); err != nil || ok || tok.ID != rex.ID {
		t.Fatalf("expired refresh: ok=%v err=%v", ok, err)
	}
	// concurrent refresh use: exactly one wins
	gc := mkCode(t, r, c.ID, u, "gc-"+uuid.NewString(), time.Minute)
	rc := mkRefresh(t, r, gc, "rtc-"+uuid.NewString(), time.Hour)
	var wins int32
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, err := r.UseRefresh(ctx, rc.TokenHash); err != nil {
				t.Errorf("UseRefresh race: %v", err)
			} else if ok {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("refresh used by %d goroutines, want 1", wins)
	}

	// ---- housekeeping in CreateRequest ----
	oldCode := mkCode(t, r, c.ID, u, "old-"+uuid.NewString(), -48*time.Hour)           // expired >1d, no refresh -> deleted
	keepCode := mkCode(t, r, c.ID, u, "keep-"+uuid.NewString(), -48*time.Hour)         // expired >1d but has refresh -> kept
	oldRT := mkRefresh(t, r, keepCode, "oldrt-"+uuid.NewString(), -48*time.Hour)       // expired >1d -> deleted
	// deleting oldRT first, then keepCode has no refresh anymore: the DELETEs run in order
	// (refresh tokens first) so keepCode becomes deletable only on the following run.
	if err := r.CreateRequest(ctx, &oidc.AuthRequest{ID: "hk-" + uuid.NewString(), ClientUUID: c.ID, RedirectURI: "x", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = r.pool.QueryRow(ctx, `SELECT count(*) FROM oauth_codes WHERE id=$1`, oldCode.ID).Scan(&n)
	if n != 0 {
		t.Fatal("expired code without refresh tokens not cleaned")
	}
	_ = r.pool.QueryRow(ctx, `SELECT count(*) FROM oauth_refresh_tokens WHERE id=$1`, oldRT.ID).Scan(&n)
	if n != 0 {
		t.Fatal("expired refresh token not cleaned")
	}
	// recent expired code (<1d) stays
	recent := mkCode(t, r, c.ID, u, "recent-"+uuid.NewString(), -time.Hour)
	if err := r.CreateRequest(ctx, &oidc.AuthRequest{ID: "hk-" + uuid.NewString(), ClientUUID: c.ID, RedirectURI: "x", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	_ = r.pool.QueryRow(ctx, `SELECT count(*) FROM oauth_codes WHERE id=$1`, recent.ID).Scan(&n)
	if n != 1 {
		t.Fatal("recent code wrongly cleaned")
	}
}

func TestOIDCIdentityDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewOIDCRepository(pool)
	ctx := context.Background()
	u := f.user("", time.Now().Add(-time.Hour))

	o1, o2, o3 := f.org(u), f.org(u), f.org(u)
	f.member(o1, u, "owner")
	f.member(o2, u, "member")
	f.member(o3, u, "admin")
	if _, err := pool.Exec(ctx, `UPDATE organizations SET deleted_at = now() WHERE id=$1`, o3); err != nil {
		t.Fatal(err)
	}
	orgs, err := r.UserOrgs(ctx, u)
	if err != nil || len(orgs) != 2 {
		t.Fatalf("UserOrgs: %v %v", orgs, err)
	}
	for _, o := range orgs {
		if o.OrgID == o3 || o.Slug == "" || (o.Role != "owner" && o.Role != "member") {
			t.Fatalf("UserOrgs row %+v", o)
		}
	}
	if none, err := r.UserOrgs(ctx, uuid.New()); err != nil || none == nil || len(none) != 0 {
		t.Fatalf("UserOrgs unknown: %v %v", none, err)
	}
}

func TestUsernameTakenDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewOIDCRepository(pool)
	ctx := context.Background()
	tag := "u" + uuid.NewString()[:8]
	base := time.Now().Add(-24 * time.Hour).UTC()

	older := f.user(tag+".Bob+x@Example.com", base)                    // local part "tag.Bob+x" -> "tag.bob-x"
	newer := f.user(tag+".bob-x@other.org", base.Add(time.Minute))     // same sanitised base, younger
	deleted := f.user(tag+"del@x.io", base.Add(-time.Hour))            // deleted older user does not own it
	if _, err := pool.Exec(ctx, `UPDATE users SET deleted_at=now() WHERE id=$1`, deleted); err != nil {
		t.Fatal(err)
	}
	// punctuation-only local part => base 'user' after btrim; long local part truncated to 32
	punct := f.user("___---..."+tag+"@x.io", base) // "___---...tag" -> trimmed leading '-._' -> tag
	_ = punct
	long := f.user(tag+"abcdefghijklmnopqrstuvwxyz0123456789@x.io", base.Add(time.Second))

	chk := func(who uuid.UUID, b string, want bool, why string) {
		t.Helper()
		got, err := r.UsernameTaken(ctx, who, b)
		if err != nil {
			t.Fatalf("%s: %v", why, err)
		}
		if got != want {
			t.Fatalf("%s: UsernameTaken(%q) = %v, want %v", why, b, got, want)
		}
	}
	b := tag + ".bob-x"
	chk(newer, b, true, "younger user loses to older with same base")
	chk(older, b, false, "older user keeps its base")
	chk(older, tag+"del", false, "deleted users never own a name")
	chk(newer, tag+"del", false, "deleted user base")
	chk(older, "no-such-"+tag, false, "unknown base")
	// the 'long' user: its own base is the first 32 chars; another younger user of the same base would lose
	lb := (tag + "abcdefghijklmnopqrstuvwxyz0123456789")[:32]
	twin := f.user(tag+"abcdefghijklmnopqrstuvwxyz0123456789zzz@x.io", base.Add(2*time.Second))
	chk(twin, lb, true, "32-char truncation matches Go SanitizeUsername")
	chk(long, lb, false, "older of truncated twins")
	// leading/trailing punctuation trimmed: "___---...tag" owned by 'punct', base == tag
	pb := oidc.SanitizeUsername("___---..." + tag + "@x.io")
	chk(f.user(tag+"@x.io", base.Add(time.Hour)), pb, true, "btrim of leading '-._' agrees with Go sanitiser (base="+pb+")")

	// SQL must agree with the Go sanitiser on a set of tricky addresses
	for _, em := range []string{"A.B+c@x.io", "ÉÑ" + tag + "@x.io", "-._" + tag + "-._@x.io", "x y_z@x.io"} {
		owner := f.user("o"+uuid.NewString()[:6]+em, base.Add(-time.Hour))
		_ = owner
	}
	for _, em := range []string{"A.B+c", "ÉÑ" + tag, "-._" + tag + "-._", "x y_z"} {
		addr := "t" + uuid.NewString()[:6] + em + "@x.io"
		older := f.user(addr, base.Add(-2*time.Hour))
		_ = older
		young := f.user("zz"+uuid.NewString()[:6]+"@x.io", base.Add(time.Hour))
		goBase := oidc.SanitizeUsername(addr)
		chk(young, goBase, true, "Go/SQL sanitiser parity for "+addr+" -> "+goBase)
	}
	// empty base case: a local part with only punctuation sanitises to 'user'
	pu := f.user("..--__@"+tag+".io", base.Add(-3*time.Hour))
	_ = pu
	chk(f.user("", base.Add(2*time.Hour)), oidc.SanitizeUsername("..--__@x.io"), true, "empty -> 'user' (base="+oidc.SanitizeUsername("..--__@x.io")+")")
}
