package gittokens_test

import (
	"context"
	"encoding/hex"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

// fakeUsers is a domain.UserRepository with only GetByID; the embedded nil interface panics if
// anything else is called, which would be a bug in NameRules.
type fakeUsers struct {
	domain.UserRepository
	m map[uuid.UUID]string
}

func newFakeUsers() *fakeUsers { return &fakeUsers{m: map[uuid.UUID]string{}} }

func (f *fakeUsers) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	email, ok := f.m[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return &domain.User{ID: id, Email: email}, nil
}

type fakeTaken struct{ taken bool }

func (f fakeTaken) UsernameTaken(context.Context, uuid.UUID, string) (bool, error) {
	return f.taken, nil
}

func hex3(id uuid.UUID) string { return hex.EncodeToString(id[:3]) }
