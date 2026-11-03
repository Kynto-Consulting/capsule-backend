package gitapi

import (
	"context"
	"sync"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// Extension points for the packages that own part of the pull request document.

var (
	hookMu     sync.RWMutex
	decorators []PullDecorator
	ownerSrc   []func(ctx context.Context, ref gitcore.RepoRef, p gitcore.Pull) ([]string, error)
)

// RegisterPullDecorator adds a function that fills fields it owns (auto_merge from B8...) on every
// Pull document the API returns.
func RegisterPullDecorator(d PullDecorator) {
	hookMu.Lock()
	decorators = append(decorators, d)
	hookMu.Unlock()
}

// DecoratePull applies the registered decorators.
func DecoratePull(ref gitcore.RepoRef, p gitcore.Pull, out *PullOut) {
	hookMu.RLock()
	list := append([]PullDecorator(nil), decorators...)
	hookMu.RUnlock()
	for _, d := range list {
		d(ref, p, out)
	}
}

// RegisterCodeownerSource adds a provider of the code owners whose review is still pending on a
// pull request (B8); the list feeds reviewsList.code_owner_pending.
func RegisterCodeownerSource(s func(ctx context.Context, ref gitcore.RepoRef, p gitcore.Pull) ([]string, error)) {
	hookMu.Lock()
	ownerSrc = append(ownerSrc, s)
	hookMu.Unlock()
}

// CodeownersPending unions the pending code owners of every source (errors are skipped: the list is
// informational, the CODEOWNER_REQUIRED blocker is what gates the merge).
func CodeownersPending(ctx context.Context, ref gitcore.RepoRef, p gitcore.Pull) []string {
	hookMu.RLock()
	list := append([]func(context.Context, gitcore.RepoRef, gitcore.Pull) ([]string, error)(nil), ownerSrc...)
	hookMu.RUnlock()
	seen := map[string]bool{}
	out := []string{}
	for _, s := range list {
		names, err := s(ctx, ref, p)
		if err != nil {
			continue
		}
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}
