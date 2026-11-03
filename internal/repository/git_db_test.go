//go:build dbtest

package repository

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

func TestGitConfigDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewGitRepository(pool, "test-secret-key")
	ctx := context.Background()
	u := f.user("", time.Now())
	org := f.org(u)
	p := f.project(org, "")

	if _, err := r.Get(ctx, p); err != domain.ErrNotFound {
		t.Fatalf("Get empty: %v", err)
	}
	in := &domain.ProjectGit{ProjectID: p, Provider: "github", RepoURL: "https://github.com/a/b.git", Branch: "main",
		AuthKind: "token", Credential: "ghp_secret", WebhookSecret: "whsec", AutoDeploy: true, PreviewEnabled: true, PreviewMax: 3, PreviewTTLHours: 24}
	out, err := r.Upsert(ctx, in)
	if err != nil {
		t.Fatalf("Upsert insert: %v", err)
	}
	if out.Credential != "ghp_secret" || out.WebhookSecret != "whsec" || !out.AutoDeploy || out.PreviewMax != 3 || out.PreviewTTLHours != 24 {
		t.Fatalf("Upsert result %+v", out)
	}
	// secrets are encrypted at rest
	var enc []byte
	if err := pool.QueryRow(ctx, `SELECT auth_enc FROM project_git WHERE project_id=$1`, p).Scan(&enc); err != nil || len(enc) == 0 || strings.Contains(string(enc), "ghp_secret") {
		t.Fatalf("auth_enc not encrypted: %v", err)
	}
	// ON CONFLICT update path; empty creds -> NULL columns
	in2 := *in
	in2.Provider, in2.Branch, in2.AuthKind, in2.Credential, in2.WebhookSecret, in2.AutoDeploy = "gitea", "dev", "none", "", "", false
	out2, err := r.Upsert(ctx, &in2)
	if err != nil || out2.Provider != "gitea" || out2.Branch != "dev" || out2.Credential != "" || out2.WebhookSecret != "" || out2.AutoDeploy {
		t.Fatalf("Upsert update: %+v %v", out2, err)
	}
	if !out2.UpdatedAt.After(out.UpdatedAt) && !out2.UpdatedAt.Equal(out.UpdatedAt) {
		t.Fatalf("updated_at went backwards")
	}
	if err := r.RotateWebhookSecret(ctx, p, "new-secret"); err != nil {
		t.Fatal(err)
	}
	g, err := r.Get(ctx, p)
	if err != nil || g.WebhookSecret != "new-secret" {
		t.Fatalf("rotate: %+v %v", g, err)
	}
	if err := r.RotateWebhookSecret(ctx, uuid.New(), "x"); err != domain.ErrNotFound {
		t.Fatalf("rotate missing: %v", err)
	}
	// CHECK constraints
	bad := *in
	bad.Provider = "svn"
	if _, err := r.Upsert(ctx, &bad); err == nil {
		t.Fatal("bad provider accepted")
	}
	bad = *in
	bad.AuthKind = "password"
	if _, err := r.Upsert(ctx, &bad); err == nil {
		t.Fatal("bad auth_kind accepted")
	}
	// wrong key must fail to decrypt, not return garbage
	wrong := NewGitRepository(pool, "other-key")
	in3 := *in
	if _, err := r.Upsert(ctx, &in3); err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Get(ctx, p); err == nil {
		t.Fatal("decrypt with wrong key succeeded")
	}
	if err := r.Delete(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, p); err != domain.ErrNotFound {
		t.Fatalf("delete twice: %v", err)
	}
	// FK: git config needs a real project
	ghost := *in
	ghost.ProjectID = uuid.New()
	if _, err := r.Upsert(ctx, &ghost); err == nil {
		t.Fatal("git config for nonexistent project accepted")
	}
}

func mkDeployment(t *testing.T, f *fx, project uuid.UUID, status, trigger string, createdAt time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.pool.QueryRow(context.Background(),
		`INSERT INTO deployments (project_id, version, status, trigger, created_at) VALUES ($1,'v1',$2,$3,$4) RETURNING id`,
		project, status, trigger, createdAt).Scan(&id); err != nil {
		t.Fatalf("insert deployment: %v", err)
	}
	return id
}

func TestPreviewsDB(t *testing.T) {
	pool := sharedPool(t)
	f := newFx(t, pool)
	r := NewGitRepository(pool, "k")
	projRepo := NewProjectRepository(pool)
	ctx := context.Background()

	u := f.user("", time.Now())
	org := f.org(u)
	parent, err := projRepo.Create(ctx, &domain.Project{OrgID: org, Name: strings.Repeat("N", 95), Slug: "par-" + uuid.NewString(),
		RepoURL: "https://example.com/r.git", Branch: "main", BuildStrategy: "auto", DeployType: "docker", Runtime: "node", Replicas: 4})
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}
	exp := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Microsecond)
	slug7 := "pr7-" + uuid.NewString()[:8]

	pv, err := r.CreatePreview(ctx, parent, 7, slug7, exp)
	if err != nil {
		t.Fatalf("CreatePreview: %v", err)
	}
	if pv.ParentProjectID != parent.ID || pv.PR != 7 || pv.Slug != slug7 || pv.Status != "created" || pv.OrgID != org ||
		pv.ExpiresAt == nil || !pv.ExpiresAt.Equal(exp) || pv.LatestDeployment != nil || pv.DeploymentStatus != "" {
		t.Fatalf("preview %+v", pv)
	}
	// copied attributes; name truncated to fit 100 chars; replicas forced to 1
	var name, runtime, deployType string
	var replicas int
	var labels string
	if err := pool.QueryRow(ctx, `SELECT name, runtime, deploy_type, replicas, labels::text FROM projects WHERE id=$1`, pv.ProjectID).Scan(&name, &runtime, &deployType, &replicas, &labels); err != nil {
		t.Fatal(err)
	}
	if len(name) > 100 || !strings.HasSuffix(name, "(PR #7)") || runtime != "node" || deployType != "docker" || replicas != 1 {
		t.Fatalf("preview project name=%q runtime=%q type=%q replicas=%d", name, runtime, deployType, replicas)
	}
	// idempotent: same PR returns the same preview (ON CONFLICT with partial unique index)
	again, err := r.CreatePreview(ctx, parent, 7, "pr7-other-"+uuid.NewString()[:8], exp)
	if err != nil || again.ProjectID != pv.ProjectID {
		t.Fatalf("CreatePreview twice: %+v %v", again, err)
	}
	// parent of a missing/deleted project: nothing inserted, GetPreview -> ErrNotFound
	if _, err := r.CreatePreview(ctx, &domain.Project{ID: uuid.New()}, 9, "x-"+uuid.NewString()[:8], exp); err != domain.ErrNotFound {
		t.Fatalf("CreatePreview missing parent: %v", err)
	}
	// slug collision inside the org (unique (org_id, slug)) must error, not silently succeed
	if _, err := r.CreatePreview(ctx, parent, 8, slug7, exp); err == nil {
		t.Fatal("duplicate slug in org accepted")
	}
	pv8, err := r.CreatePreview(ctx, parent, 8, "pr8-"+uuid.NewString()[:8], exp.Add(-72*time.Hour))
	if err != nil {
		t.Fatalf("CreatePreview 8: %v", err)
	}

	// the unique index itself, and its soft-delete exemption
	if _, err := pool.Exec(ctx, `INSERT INTO projects (org_id,name,slug,parent_project_id,preview_pr) VALUES ($1,'x',$2,$3,7)`, org, "dup-"+uuid.NewString(), parent.ID); err == nil {
		t.Fatal("unique (parent_project_id, preview_pr) not enforced")
	}
	// two normal projects (NULL parent) never collide
	f.project(org, "")
	f.project(org, "")

	// listings hide / show previews
	hidden, total, err := projRepo.ListByOrg(ctx, org, 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range hidden {
		if p.ID == pv.ProjectID || p.ID == pv8.ProjectID {
			t.Fatal("ListByOrg returned a preview project")
		}
	}
	incl, totalIncl, err := projRepo.ListByOrgIncludingPreviews(ctx, org, 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if totalIncl != total+2 || len(incl) != len(hidden)+2 {
		t.Fatalf("including previews: %d/%d vs hidden %d/%d", len(incl), totalIncl, len(hidden), total)
	}
	if page2, _, err := projRepo.ListByOrgIncludingPreviews(ctx, org, 2, 2); err != nil || len(page2) != 2 {
		t.Fatalf("pagination offset: %d %v", len(page2), err)
	}

	// latest deployment + status in listing
	dOld := mkDeployment(t, f, pv.ProjectID, "failed", "git", time.Now().Add(-time.Hour))
	dNew := mkDeployment(t, f, pv.ProjectID, "queued", "git", time.Now())
	_ = dOld
	l, err := r.ListPreviews(ctx, parent.ID)
	if err != nil || len(l) != 2 || l[0].ProjectID != pv.ProjectID || l[0].LatestDeployment == nil || *l[0].LatestDeployment != dNew || l[0].DeploymentStatus != "queued" {
		t.Fatalf("ListPreviews: %+v %v", l, err)
	}
	if l[1].LatestDeployment != nil {
		t.Fatalf("pv8 should have no deployment")
	}

	// expiry listing
	exps, err := r.ListExpiredPreviews(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	found8, found7 := false, false
	for _, e := range exps {
		found8 = found8 || e.ProjectID == pv8.ProjectID
		found7 = found7 || e.ProjectID == pv.ProjectID
	}
	if !found8 || found7 {
		t.Fatalf("expired set wrong: pv8=%v pv7=%v", found8, found7)
	}
	if err := r.TouchPreview(ctx, pv8.ProjectID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	exps, _ = r.ListExpiredPreviews(ctx, time.Now())
	for _, e := range exps {
		if e.ProjectID == pv8.ProjectID {
			t.Fatal("touched preview still expired")
		}
	}
	// Touch on a non-preview project is a no-op
	if err := r.TouchPreview(ctx, parent.ID, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	var pexp *time.Time
	_ = pool.QueryRow(ctx, `SELECT expires_at FROM projects WHERE id=$1`, parent.ID).Scan(&pexp)
	if pexp != nil {
		t.Fatal("TouchPreview modified a non-preview project")
	}
	if err := r.SetPreviewComment(ctx, pv.ProjectID, 9_000_000_000_123); err != nil {
		t.Fatal(err)
	}
	gp, err := r.GetPreview(ctx, parent.ID, 7)
	if err != nil || gp.CommentID != 9_000_000_000_123 {
		t.Fatalf("comment id: %+v %v", gp, err)
	}
	if is, err := r.IsPreview(ctx, pv.ProjectID); err != nil || !is {
		t.Fatalf("IsPreview: %v %v", is, err)
	}
	if is, err := r.IsPreview(ctx, parent.ID); err != nil || is {
		t.Fatalf("IsPreview parent: %v %v", is, err)
	}
	if _, err := r.IsPreview(ctx, uuid.New()); err != domain.ErrNotFound {
		t.Fatalf("IsPreview missing: %v", err)
	}

	// CancelSupersededGit
	dRun := mkDeployment(t, f, pv.ProjectID, "running", "git", time.Now())
	dManual := mkDeployment(t, f, pv.ProjectID, "queued", "manual", time.Now())
	ids, err := r.CancelSupersededGit(ctx, pv.ProjectID, dRun)
	if err != nil || len(ids) != 1 || ids[0] != dNew {
		t.Fatalf("CancelSupersededGit: %v %v (want only %s)", ids, err, dNew)
	}
	if s, _ := r.DeploymentStatus(ctx, dNew); s != "cancelled" {
		t.Fatalf("status %s", s)
	}
	if s, _ := r.DeploymentStatus(ctx, dManual); s != "queued" {
		t.Fatalf("manual deployment touched: %s", s)
	}
	if _, err := r.DeploymentStatus(ctx, uuid.New()); err != domain.ErrNotFound {
		t.Fatalf("DeploymentStatus missing: %v", err)
	}
	if ids, err := r.CancelSupersededGit(ctx, pv.ProjectID, dRun); err != nil || len(ids) != 0 {
		t.Fatalf("second cancel: %v %v", ids, err)
	}

	// DestroyPreview: cleanup + slug rename + re-creatable
	if _, err := pool.Exec(ctx, `INSERT INTO domains (project_id, org_id, domain_name) VALUES ($1,$3,$2)`, pv.ProjectID, uuid.NewString()+".example.com", org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO env_vars (project_id, key, value_enc) VALUES ($1,'K',convert_to('v','UTF8'))`, pv.ProjectID); err != nil {
		t.Fatal(err)
	}
	dQ := mkDeployment(t, f, pv.ProjectID, "queued", "git", time.Now())
	if err := r.DestroyPreview(ctx, pv.ProjectID); err != nil {
		t.Fatalf("DestroyPreview: %v", err)
	}
	var st, newSlug string
	var del *time.Time
	var ex *time.Time
	if err := pool.QueryRow(ctx, `SELECT status, slug, deleted_at, expires_at FROM projects WHERE id=$1`, pv.ProjectID).Scan(&st, &newSlug, &del, &ex); err != nil {
		t.Fatal(err)
	}
	if st != "archived" || del == nil || ex != nil || newSlug != slug7+"-del-"+pv.ProjectID.String()[:8] {
		t.Fatalf("destroyed row status=%s slug=%s del=%v exp=%v", st, newSlug, del, ex)
	}
	var nd, ne int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM domains WHERE project_id=$1`, pv.ProjectID).Scan(&nd)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM env_vars WHERE project_id=$1`, pv.ProjectID).Scan(&ne)
	if nd != 0 || ne != 0 {
		t.Fatalf("leftovers domains=%d env=%d", nd, ne)
	}
	if s, _ := r.DeploymentStatus(ctx, dQ); s != "cancelled" {
		t.Fatalf("queued deployment after destroy: %s", s)
	}
	if s, _ := r.DeploymentStatus(ctx, dRun); s != "running" {
		t.Fatalf("running deployment should be left alone: %s", s)
	}
	if err := r.DestroyPreview(ctx, pv.ProjectID); err != domain.ErrNotFound {
		t.Fatalf("destroy twice: %v", err)
	}
	if err := r.DestroyPreview(ctx, parent.ID); err != domain.ErrNotFound {
		t.Fatalf("destroy of a normal project must be refused: %v", err)
	}
	if _, err := r.GetPreview(ctx, parent.ID, 7); err != domain.ErrNotFound {
		t.Fatalf("destroyed preview visible: %v", err)
	}
	for _, p := range mustList(t, r, parent.ID) {
		if p.ProjectID == pv.ProjectID {
			t.Fatal("destroyed preview in ListPreviews")
		}
	}
	// the same PR number + same slug can be re-opened (partial unique index + renamed slug)
	re, err := r.CreatePreview(ctx, parent, 7, slug7, exp)
	if err != nil || re.ProjectID == pv.ProjectID || re.Slug != slug7 {
		t.Fatalf("re-create after destroy: %+v %v", re, err)
	}
	if hidden2, _, _ := projRepo.ListByOrg(ctx, org, 1, 50); len(hidden2) != len(hidden) {
		t.Fatal("previews leaked into ListByOrg after recreate")
	}

	// concurrent creation of the same PR: one row, everyone sees it
	var wg sync.WaitGroup
	ids2 := make([]uuid.UUID, 8)
	slugC := "pr99-" + uuid.NewString()[:8]
	for i := range ids2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, err := r.CreatePreview(ctx, parent, 99, slugC, exp)
			if err != nil {
				t.Errorf("concurrent CreatePreview: %v", err)
				return
			}
			ids2[i] = p.ProjectID
		}(i)
	}
	wg.Wait()
	var rows int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM projects WHERE parent_project_id=$1 AND preview_pr=99 AND deleted_at IS NULL`, parent.ID).Scan(&rows)
	if rows != 1 {
		t.Fatalf("concurrent CreatePreview made %d rows", rows)
	}
	for _, id := range ids2 {
		if id != ids2[0] {
			t.Fatalf("goroutines saw different previews: %v", ids2)
		}
	}
}

func mustList(t *testing.T, r *GitRepository, parent uuid.UUID) []*domain.Preview {
	t.Helper()
	l, err := r.ListPreviews(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
