//go:build dbtest

package repository

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/vpn"
)

const k44db = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// The VPN/functions stores against real Postgres (docs/vpn-connector.md): uniqueness, concurrency, tokens, CAS cron, audit.
func TestVPNFunctionsPostgres(t *testing.T) {
	pool := sharedPool(t)
	ctx := context.Background()
	f := newFx(t, pool)
	user := f.user("vpn-"+uuid.NewString()[:8]+"@example.com", time.Now())
	org := f.org(user)
	proj := f.project(org, "p-"+uuid.NewString()[:8])
	proj2 := f.project(org, "q-"+uuid.NewString()[:8])

	vs := &vpn.Service{Store: &vpn.PGStore{Pool: pool}, SecretKey: "unit-test-key-0123456789abcdef"}
	fs := &fn.Service{Store: &fn.PGStore{Pool: pool}, VPN: vs}
	spec := vpn.Spec{Name: "estudio", Provider: "wireguard", Host: "1.2.3.4:51820", CIDRs: []string{"10.48.0.0/24"},
		Secret: `{"private_key":"` + k44db + `","peer_public_key":"` + k44db + `","address":"10.99.0.2/32"}`}
	tn, err := vs.Create(ctx, org, proj, "user:ana", &user, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Create(ctx, org, proj, "user:ana", &user, spec); !errors.Is(err, vpn.ErrConflict) {
		t.Fatalf("one tunnel per project: %v", err)
	}
	got, err := vs.Store.GetByName(ctx, proj, "estudio")
	if err != nil || len(got.SecretEnc) == 0 || got.CIDRs[0] != "10.48.0.0/24" || !got.HasSecret {
		t.Fatalf("%+v %v", got, err)
	}
	if plain, err := vs.Secret(got); err != nil || plain != spec.Secret {
		t.Fatal("secret roundtrip", err)
	}

	// a tunnel of another project is invisible to a function
	if _, err := fs.Deploy(ctx, org, proj2, &user, fn.Spec{Name: "migrar", Image: "i", VPN: "estudio"}); !errors.Is(err, fn.ErrInvalid) {
		t.Fatalf("cross-project tunnel: %v", err)
	}
	fnc, err := fs.Deploy(ctx, org, proj, &user, fn.Spec{Name: "migrar", Image: "i", VPN: "estudio", Cron: "0 2 * * *", Scopes: []string{"api:importacion"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Deploy(ctx, org, proj, &user, fn.Spec{Name: "migrar", Image: "i"}); !errors.Is(err, fn.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}

	r1, err := fs.Enqueue(ctx, fnc, fn.TriggerAPI, "user:ana", []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := fs.Enqueue(ctx, fnc, fn.TriggerQueue, "user:ana", nil)
	a1, err := fs.Claim(ctx, "n1")
	if err != nil || a1 == nil || a1.Run.ID != r1.ID || strings.ReplaceAll(string(a1.Run.Payload), " ", "") != `{"a":1}` {
		t.Fatalf("claim: %+v %v", a1, err)
	}
	if a2, _ := fs.Claim(ctx, "n2"); a2 != nil {
		t.Fatal("concurrency 1 violated")
	}
	c := fs.Introspect(ctx, a1.Token)
	if !c.Active || !c.HasScope("api:importacion") || c.Function != "migrar" {
		t.Fatalf("%+v", c)
	}
	exit := 0
	if err := fs.Finish(ctx, r1.ID, fn.RunSucceeded, &exit, 10, 20, "ok"); err != nil {
		t.Fatal(err)
	}
	if fs.Introspect(ctx, a1.Token).Active {
		t.Fatal("token must be revoked")
	}
	if a2, _ := fs.Claim(ctx, "n2"); a2 == nil || a2.Run.ID != r2.ID {
		t.Fatal("second run should start now")
	}

	// compare-and-set cron: two instances, one wins
	now := time.Now()
	ok1, _ := fs.Store.CASLastCron(ctx, fnc.ID, fnc.LastCronAt, now)
	ok2, _ := fs.Store.CASLastCron(ctx, fnc.ID, fnc.LastCronAt, now.Add(time.Second))
	if !ok1 || ok2 {
		t.Fatalf("cas %v %v", ok1, ok2)
	}

	// kill switch + audit trail
	if err := fs.DisableTunnel(ctx, tn, "user:ana"); err != nil {
		t.Fatal(err)
	}
	ev, _ := vs.Store.Events(ctx, tn.ID, 20)
	kinds := map[string]bool{}
	for _, e := range ev {
		kinds[e.Kind] = true
	}
	for _, k := range []string{vpn.EventCreated, vpn.EventRunStarted, vpn.EventRunFinished, vpn.EventDisabled} {
		if !kinds[k] {
			t.Errorf("missing audit event %s in %v", k, kinds)
		}
	}
	if _, err := fs.Enqueue(ctx, fnc, fn.TriggerAPI, "u", nil); !errors.Is(err, fn.ErrDisabled) {
		t.Fatalf("enqueue on disabled tunnel: %v", err)
	}
	// deleting the tunnel keeps the audit
	if err := vs.Delete(ctx, tn, "user:ana"); err != nil {
		t.Fatal(err)
	}
	if ev, _ := vs.Store.Events(ctx, tn.ID, 5); len(ev) == 0 {
		t.Fatal("audit must survive tunnel deletion")
	}
	// nodes
	pg := &fn.PGStore{Pool: pool}
	tok, err := pg.CreateNode(ctx, "nodo-"+uuid.NewString()[:6])
	if err != nil {
		t.Fatal(err)
	}
	if name, err := pg.NodeByHash(ctx, fn.HashToken(tok)); err != nil || name == "" {
		t.Fatalf("node auth: %v", err)
	}
}
