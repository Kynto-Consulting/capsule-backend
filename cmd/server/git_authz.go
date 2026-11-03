package main

import (
	"context"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
)

// gitAuthorizer maps the Git module's two questions onto the project role matrix:
// managing the link (credentials, auto-deploy, previews) is a project operation,
// and reading it (link status, previews) only needs read access, so viewers can see it.
type gitAuthorizer struct{ svc *authz.Service }

func (a gitAuthorizer) CanManage(ctx context.Context, userID, orgID, projectID uuid.UUID) (bool, error) {
	return a.svc.Can(ctx, userID, orgID, projectID, authz.ProjectOps)
}

func (a gitAuthorizer) CanDeploy(ctx context.Context, userID, orgID, projectID uuid.UUID) (bool, error) {
	return a.svc.Can(ctx, userID, orgID, projectID, authz.ProjectRead)
}
