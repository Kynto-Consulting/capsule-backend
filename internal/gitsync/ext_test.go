package gitsync_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitcore/fake"
	"github.com/kynto/capsule/backend/internal/gitsync"
)

type linkRec struct {
	*ids
	linked map[uuid.UUID]int64
}

func (l *linkRec) MarkLinked(_ context.Context, id uuid.UUID, fid int64) error {
	l.linked[id] = fid
	return nil
}

func TestWithExtPatchesAdminTeamAndFillsForgejoUserID(t *testing.T) {
	fs := fake.New()
	t.Cleanup(fs.Close)
	svc := gitcore.New(gitcore.Config{URL: fs.URL, Token: fake.Token, Timeout: 2 * time.Second, BackoffBase: time.Millisecond, BackoffMax: 4 * time.Millisecond}, nil, nil)
	ctx := context.Background()
	fs.AddRepo("acme", "api")
	fs.AddUser("ana")
	// the previous wave created the -admin team with permission admin
	old, err := svc.EnsureTeam(ctx, "acme", gitcore.TeamSpec{Name: "api-admin", Permission: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	p, ana := uuid.New(), uuid.New()
	d := &dir{
		info:    &gitsync.ProjectInfo{ID: p, OrgID: uuid.New(), Slug: "api", Repo: gitcore.RepoRef{Owner: "acme", Repo: "api"}},
		members: []gitsync.Member{{UserID: ana, Email: "ana@x.io", OrgRole: "owner"}},
	}
	store := &linkRec{ids: &ids{rows: map[uuid.UUID]*gitsync.Identity{}}, linked: map[uuid.UUID]int64{}}
	rec := &gitsync.Reconciler{Forge: gitsync.WithExt(svc), Dir: d, IDs: &gitsync.Identities{Store: store}}
	rep, err := rec.Reconcile(ctx, p, gitsync.TriggerPeriodic)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.PermissionDrift) != 1 || rep.PermissionDrift[0] != "api-admin" {
		t.Fatalf("drift: %+v", rep)
	}
	patched := false
	for _, rq := range fs.Requests() {
		if rq.Method == "PATCH" && rq.Path == "/api/v1/teams/"+itoa(old.ID) {
			patched = true
		}
	}
	if !patched {
		t.Fatal("the team permission was not patched in Forgejo")
	}
	if fid := store.linked[ana]; fid < 1 {
		t.Fatalf("forgejo_user_id not filled: %d", fid)
	}
	_ = authz.RoleAdmin
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
