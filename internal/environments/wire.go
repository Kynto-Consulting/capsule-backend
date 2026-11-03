package environments

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

var (
	sharedMu sync.RWMutex
	shared   *Service
)

// Shared returns the Service published by WireEnvironments (nil before wiring).
func Shared() *Service {
	sharedMu.RLock()
	defer sharedMu.RUnlock()
	return shared
}

// SetShared publishes the process-wide Service (tests and WireEnvironments).
func SetShared(s *Service) {
	sharedMu.Lock()
	shared = s
	sharedMu.Unlock()
}

// AdminCounter counts effective project admins (authz.MemberStore provides it).
type AdminCounter interface {
	CountEffectiveAdmins(ctx context.Context, orgID, projectID uuid.UUID) (int, error)
}

// Deps are the collaborators WireEnvironments needs from the rest of the backend.
type Deps struct {
	Store       Store
	Deployments domain.DeploymentRepository
	Users       domain.UserRepository
	Authz       *authz.Service
	Admins      AdminCounter
	Security    SecurityGate // optional (package B7)
}

// WireEnvironments builds the Service on the shared gitcore Core and event publisher, publishes it
// and starts the loop (cfg from ENVIRONMENTS_*). Called from the git-capsule:wiring block of
// cmd/server/main.go.
func WireEnvironments(ctx context.Context, logger *slog.Logger, d Deps) *Service {
	svc := New(d.Store, gitcore.Shared(), NewRepoDeployer(d.Deployments), NewDirectory(d.Authz, d.Users, d.Admins),
		gitevents.Shared(), ConfigFromEnv(), logger)
	if d.Security != nil {
		svc.WithSecurity(d.Security)
	}
	SetShared(svc)
	go svc.RunLoop(ctx)
	if logger != nil {
		logger.Info("environments ready", "tick", svc.cfg.Tick.String())
	}
	return svc
}

// ---- Deployer over the existing deployment repository -----------------------------------------------

type repoDeployer struct{ deps domain.DeploymentRepository }

// NewRepoDeployer creates deployments through the existing repository: a queued deployment with
// the SAME stored source, which the existing worker processes (same path as rollback). Nothing is
// cloned, packaged or uploaded here.
func NewRepoDeployer(d domain.DeploymentRepository) Deployer { return repoDeployer{d} }

func (r repoDeployer) Deploy(ctx context.Context, projectID uuid.UUID, a Artifact, by *uuid.UUID, meta map[string]string) (uuid.UUID, error) {
	key := a.SourceKey
	d, err := r.deps.Create(ctx, &domain.Deployment{
		ProjectID: projectID, Version: "promotion-" + short(a.SHA), GitSHA: a.SHA,
		BuildStrategy: a.BuildStrategy, ContainerPort: a.ContainerPort,
		Trigger: "promotion", TriggeredBy: by, SourceKey: &key, Meta: meta,
	})
	if err != nil {
		return uuid.Nil, err
	}
	_ = r.deps.AppendLog(ctx, &domain.BuildLog{DeploymentID: d.ID, Level: "info",
		Message: "Promotion: reusing the stored source of deployment " + a.DeploymentID.String()})
	return d.ID, nil
}

func (r repoDeployer) Status(ctx context.Context, id uuid.UUID) (string, string, error) {
	d, err := r.deps.GetByID(ctx, id)
	if err != nil {
		return "", "", err
	}
	h := ""
	if d.Health != nil {
		h = d.Health.Status
	}
	return d.Status, h, nil
}

func short(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

// ---- Directory over authz and the user repository -----------------------------------------------------

type directory struct {
	az     *authz.Service
	users  domain.UserRepository
	admins AdminCounter
}

// NewDirectory resolves roles with authz, people with the user repository and counts admins.
func NewDirectory(az *authz.Service, users domain.UserRepository, admins AdminCounter) Directory {
	return directory{az, users, admins}
}

func (d directory) Role(ctx context.Context, userID, orgID, projectID uuid.UUID) (authz.Role, error) {
	acc, err := d.az.Access(ctx, userID, orgID, projectID)
	if err != nil {
		return "", err
	}
	if !acc.Member || acc.Hidden {
		return "", nil
	}
	return acc.Role, nil
}

func (d directory) Person(ctx context.Context, id uuid.UUID) (Person, error) {
	u, err := d.users.GetByID(ctx, id)
	if err != nil {
		return Person{}, err
	}
	p := Person{Name: u.Name, Email: u.Email}
	if u.AvatarURL != nil {
		p.AvatarURL = *u.AvatarURL
	}
	return p, nil
}

func (d directory) CountAdmins(ctx context.Context, orgID, projectID uuid.UUID) (int, error) {
	if d.admins == nil {
		return 0, errors.New("environments: no admin counter configured")
	}
	return d.admins.CountEffectiveAdmins(ctx, orgID, projectID)
}
