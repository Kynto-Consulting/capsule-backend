package gittokens_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitsync"
	"github.com/kynto/capsule/backend/internal/gittokens"
	"github.com/kynto/capsule/backend/internal/gittokens/gittokenstest"
)

type syncIDStore struct{ rows map[uuid.UUID]*gitsync.Identity }

func (s *syncIDStore) Get(_ context.Context, id uuid.UUID) (*gitsync.Identity, error) {
	if r := s.rows[id]; r != nil {
		return r, nil
	}
	return nil, gitsync.ErrNoIdentity
}
func (s *syncIDStore) Ensure(_ context.Context, id uuid.UUID, l string) (*gitsync.Identity, error) {
	if r := s.rows[id]; r != nil {
		return r, nil
	}
	s.rows[id] = &gitsync.Identity{UserID: id, ForgejoUsername: l}
	return s.rows[id], nil
}
func (s *syncIDStore) MarkLinked(context.Context, uuid.UUID, int64) error { return nil }

type userStub struct {
	domain.UserRepository
	users map[uuid.UUID]*domain.User
}

func (u userStub) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if x := u.users[id]; x != nil {
		return x, nil
	}
	return nil, domain.ErrNotFound
}

// The login the internal endpoint puts in X-WEBAUTH-USER is the one A2 registers in
// git_identities (and uses to fill the Forgejo teams), including the suffix when a name is taken.
func TestGitsyncIdentityMatchesWhatA2Registers(t *testing.T) {
	e := newEnv(t, gittokens.Config{})
	rows := map[uuid.UUID]*gitsync.Identity{}
	ids := &gitsync.Identities{Store: &syncIDStore{rows: rows}, Taken: func(_ context.Context, id uuid.UUID, base string) (bool, error) {
		return id == e.bob && base == "bob", nil // an older account owns "bob"
	}}
	users := userStub{users: map[uuid.UUID]*domain.User{
		e.alice: {ID: e.alice, Email: "alice@x.io"},
		e.bob:   {ID: e.bob, Email: "bob@x.io"},
	}}
	svc := gittokens.New(gittokens.Config{}, gittokens.Deps{
		Store: e.store, Access: e.access, Directory: &gittokenstest.Directory{Projects: []gittokens.ProjectRef{e.web}},
		Identity: gittokens.GitsyncIdentity{IDs: func() *gitsync.Identities { return ids }, Users: users},
		Sessions: e.sessions, Now: e.clock.Now, Async: func(f func()) { f() },
	})
	for _, u := range []uuid.UUID{e.alice, e.bob} {
		c, err := svc.Issue(context.Background(), u, gittokens.IssueInput{Path: "acme/web", SessionRef: "cli:s1", IP: "203.0.113.9"})
		if err != nil {
			t.Fatal(err)
		}
		d := svc.Authenticate(context.Background(), gittokens.AuthRequest{HasBasic: true, User: "x", Password: c.Password, Method: "GET", URI: fetchRefs, IP: "1.2.3.4"})
		if d.Outcome != gittokens.OutcomeAllow {
			t.Fatalf("auth: %+v", d)
		}
		reg, err := ids.Resolve(context.Background(), u, users.users[u].Email) // what A2's reconciler uses
		if err != nil || d.Login != reg.ForgejoUsername || c.Username != reg.ForgejoUsername {
			t.Fatalf("endpoint login %q / credential %q differ from A2's %q (%v)", d.Login, c.Username, reg.ForgejoUsername, err)
		}
		if rows[u] == nil || rows[u].ForgejoUsername != d.Login {
			t.Fatal("identity not stored")
		}
	}
	if rows[e.bob].ForgejoUsername == "bob" {
		t.Fatal("the taken-name suffix was not applied")
	}
	// git sync off: the fallback decides
	off := gittokens.GitsyncIdentity{IDs: func() *gitsync.Identities { return nil }, Fallback: e.ident}
	if l, err := off.ForgejoLogin(context.Background(), e.alice); err != nil || l != "alice" {
		t.Fatalf("fallback: %q %v", l, err)
	}
}
