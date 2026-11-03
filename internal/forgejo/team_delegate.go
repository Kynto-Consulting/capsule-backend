package forgejo

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// TeamSyncFunc synchronizes the Forgejo teams of one project (see gitsync.Reconciler.SyncProject).
type TeamSyncFunc func(ctx context.Context, projectID uuid.UUID) error

var (
	delegateMu sync.RWMutex
	delegate   TeamSyncFunc
)

// SetTeamSyncDelegate makes Core.SyncProject (and so provisioning, the member hooks and the
// pending-user retry) run fn instead of the built-in synchronization. nil restores the built-in.
func SetTeamSyncDelegate(fn TeamSyncFunc) {
	delegateMu.Lock()
	delegate = fn
	delegateMu.Unlock()
}

func teamSyncDelegate() TeamSyncFunc {
	delegateMu.RLock()
	defer delegateMu.RUnlock()
	return delegate
}
