package handlers

import (
	"sync"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
)

// GitCoreHooks are the notifications the core Git integration listens to. Every
// hook must return quickly (they only schedule background work) and never fail
// the original operation.
type GitCoreHooks struct {
	ProjectCreated func(p *domain.Project)
	MembersChanged func(orgID, projectID uuid.UUID) // project role added/changed/removed
	OrgChanged     func(orgID uuid.UUID)            // access mode or org membership changed
}

var (
	coreHooksMu sync.RWMutex
	coreHooks   GitCoreHooks
)

// SetGitCoreHooks installs the hooks (called once from main).
func SetGitCoreHooks(h GitCoreHooks) {
	coreHooksMu.Lock()
	coreHooks = h
	coreHooksMu.Unlock()
}

func notifyProjectCreated(p *domain.Project) {
	coreHooksMu.RLock()
	fn := coreHooks.ProjectCreated
	coreHooksMu.RUnlock()
	if fn != nil && p != nil {
		fn(p)
	}
}

func notifyMembersChanged(orgID, projectID uuid.UUID) {
	coreHooksMu.RLock()
	fn := coreHooks.MembersChanged
	coreHooksMu.RUnlock()
	if fn != nil {
		fn(orgID, projectID)
	}
}

func notifyOrgChanged(orgID uuid.UUID) {
	coreHooksMu.RLock()
	fn := coreHooks.OrgChanged
	coreHooksMu.RUnlock()
	if fn != nil {
		fn(orgID)
	}
}
