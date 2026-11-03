//go:build dbtest

package api

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gateway/store"
	"github.com/kynto/capsule/backend/internal/repository"
)

// End to end against a throwaway Postgres in TEST_DATABASE_URL (a LOCAL database; never production): real migrations, the real
// store, real project ports and their rules as the IP list, the real cgs_ token table.
func TestE2EControlPlaneAgainstPostgres(t *testing.T) {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	name := "gwapi_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+name); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(base)
	u.Path = "/" + name
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
		admin.Close()
	})
	if err := repository.RunMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	var owner, org, proj uuid.UUID
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(pool.QueryRow(ctx, `INSERT INTO users (email, password_hash, name) VALUES ($1,'x','T') RETURNING id`, uuid.NewString()+"@x.io").Scan(&owner))
	must(pool.QueryRow(ctx, `INSERT INTO organizations (name, slug, owner_id) VALUES ('O',$2,$1) RETURNING id`, owner, "o-"+uuid.NewString()).Scan(&org))
	must(pool.QueryRow(ctx, `INSERT INTO projects (org_id, name, slug, repo_url, branch, runtime) VALUES ($1,'P','shop','https://example.com/r.git','main','node') RETURNING id`, org).Scan(&proj))
	project := &domain.Project{ID: proj, OrgID: org, Slug: "shop"}

	ports := repository.NewProjectPortRepository(pool)
	_, err = ports.Replace(ctx, proj, []*domain.ProjectPort{{ID: uuid.New(), ProjectID: proj, Name: "Admin Panel", ContainerPort: 9000, HostPort: 41010}})
	must(err)
	_, err = ports.AddRule(ctx, proj, 9000, "tcp", &domain.PortRule{ID: uuid.New(), CIDR: "203.0.113.0/24"}, 10)
	must(err)

	tokUser := uuid.New()
	apiTok := fakeAPITokens{m: map[string]*domain.APIToken{}}
	capPlain := "cap_" + uuid.NewString() + uuid.NewString()
	apiTok.m[sha256Hex(capPlain)] = &domain.APIToken{ID: uuid.New(), UserID: tokUser}
	st := store.NewPgStore(pool)
	svc, err := New(Deps{
		Store: st, Projects: fakeProjects{m: map[uuid.UUID]*domain.Project{proj: project}}, Orgs: fakeOrgs{roles: map[uuid.UUID]string{owner: "owner"}},
		Users: fakeUsers{gone: map[uuid.UUID]bool{}}, Authz: fakeAuthz{m: map[uuid.UUID]authz.Access{tokUser: {Role: authz.RoleDeployer, Member: true}, owner: {Role: authz.RoleAdmin, Member: true}}},
		APITokens: apiTok, SvcTokens: NewPgServiceTokens(pool),
		IPLists: RepoIPLists{Ports: ports}, Sources: RepoSources{PortRepo: ports}, Audit: &fakeAudit{},
		Config: Config{Secret: "x", Zone: "example.test", PoolLo: 25000, PoolHi: 25004, SigningKey: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", TCPHost: "tcp.example.test"},
	})
	must(err)
	actor := Actor{UserID: owner}

	n, err := SeedPool(ctx, st, svc.Config())
	must(err)
	if n != 5 {
		t.Fatalf("seeded %d, want 5", n)
	}

	// the existing published port is mirrored as it is today (direct on, gateway off)
	list, err := svc.ListServices(ctx, project)
	must(err)
	if len(list) != 1 || list[0].Name != "admin-panel" || list[0].DefaultAccess != "direct_port" {
		t.Fatalf("mirror: %+v", list)
	}
	info, err := svc.ConnectionInfo(ctx, project, "admin-panel")
	must(err)
	if len(info.ConnectionStrings) != 1 || info.ConnectionString != "tcp.example.test:41010" {
		t.Fatalf("legacy info: %+v", info)
	}
	on := true
	if _, err := svc.UpdateService(ctx, project, actor, "admin-panel", UpdateInput{GatewayEnabled: &on}); err != nil {
		t.Fatal(err)
	}
	snap, changed, err := svc.WaitRoutes(ctx, -1, 0)
	must(err)
	if !changed || len(snap.Routes) != 1 || snap.Routes[0].DestPort != 41010 || snap.Routes[0].Host != "admin-panel-shop.apps.example.test" {
		t.Fatalf("snapshot: %+v", snap)
	}
	route := snap.Routes[0].ID
	req := AuthorizeRequest{RouteID: route.String(), SrcIP: "203.0.113.50", CredentialType: CredCap, Credential: capPlain, Access: "capsule_uri"}
	if res, err := svc.Authorize(ctx, req); err != nil || !res.Allow {
		t.Fatalf("allowed ip: %v %+v", err, res)
	}
	req.SrcIP = "198.51.100.1"
	if res, _ := svc.Authorize(ctx, req); res.Allow || res.DenyReason != DenyIPDenied {
		t.Fatalf("ip outside the port rules: %+v", res)
	}
	if _, changed, err := svc.WaitRoutes(ctx, snap.Rev, 0); err != nil || changed {
		t.Fatalf("same revision must be unchanged: %v %v", changed, err)
	}
	tk, err := svc.CreateServiceToken(ctx, project, actor, ServiceTokenInput{Name: "ci", Service: "admin-panel"})
	must(err)
	req = AuthorizeRequest{RouteID: route.String(), SrcIP: "203.0.113.51", CredentialType: CredCgs, Credential: tk.Token}
	if res, _ := svc.Authorize(ctx, req); !res.Allow {
		t.Fatalf("cgs: %+v", res)
	}
	must(svc.RevokeServiceToken(ctx, project, actor, tk.ID))
	if res, _ := svc.Authorize(ctx, req); res.Allow {
		t.Fatal("revoked cgs must not connect")
	}
	ct, err := svc.IssueConnectionToken(ctx, project, Actor{UserID: tokUser}, "admin-panel")
	must(err)
	req = AuthorizeRequest{RouteID: route.String(), SrcIP: "203.0.113.52", CredentialType: CredCgc, Credential: ct.Token}
	if res, _ := svc.Authorize(ctx, req); !res.Allow {
		t.Fatalf("cgc: %+v", res)
	}
	if res, _ := svc.Authorize(ctx, req); res.Allow {
		t.Fatal("cgc is single use")
	}
	// random port: lease, release into quarantine
	lease, err := svc.LeasePort(ctx, project, actor, "admin-panel")
	must(err)
	if lease.Port < 25000 || lease.Port > 25004 {
		t.Fatalf("lease %d", lease.Port)
	}
	// exhaust the 5-port pool with more services, then expect port_pool_exhausted
	var last error
	for i := 0; i < 5; i++ {
		nm := fmt.Sprintf("s%d", i)
		if _, err := svc.CreateService(ctx, project, actor, CreateInput{Name: nm, ContainerPort: 80 + i}); err != nil {
			t.Fatal(err)
		}
		_, last = svc.LeasePort(ctx, project, actor, nm)
	}
	if ee, ok := asError(last); !ok || (ee.Code != "port_pool_exhausted" && ee.Code != "port_quota_exceeded") {
		t.Fatalf("expected exhaustion or quota, got %v", last)
	}
	must(svc.ReleasePort(ctx, project, actor, "admin-panel"))
	stats, _ := st.PoolStats(ctx)
	if stats.Quarantine != 1 {
		t.Fatalf("released port must be in quarantine: %+v", stats)
	}
	pol, err := svc.SetOrgPolicy(ctx, org, actor, "error")
	must(err)
	if pol.GatewayPolicy != "error" {
		t.Fatal("policy")
	}
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		RunSweeper(cctx, st, Config{SweepInterval: 20 * time.Millisecond}, nil, svc.notify)
		close(done)
	}()
	time.Sleep(60 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("sweeper did not stop")
	}
}
