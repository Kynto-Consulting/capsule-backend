package gitsync

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

// DomainDirectory implements Directory on the existing repositories. Roles may be nil
// (open mode, no explicit roles), exactly like the legacy sync.
type DomainDirectory struct {
	Projects domain.ProjectRepository
	Orgs     domain.OrganizationRepository
	Git      domain.GitRepository
	Roles    authz.MemberStore
}

var _ Directory = DomainDirectory{}

// Project returns the project with the Forgejo owner/repo of its link, or (nil, nil).
func (d DomainDirectory) Project(ctx context.Context, projectID uuid.UUID) (*ProjectInfo, error) {
	link, err := d.Git.Get(ctx, projectID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if link.Provider != "forgejo" {
		return nil, nil
	}
	owner, repo, ok := splitRepoURL(link.RepoURL)
	if !ok {
		return nil, nil
	}
	p, err := d.Projects.GetByID(ctx, projectID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ProjectInfo{ID: p.ID, OrgID: p.OrgID, Slug: p.Slug, Repo: gitcore.RepoRef{Owner: owner, Repo: repo}}, nil
}

func (d DomainDirectory) Members(ctx context.Context, orgID uuid.UUID) ([]Member, error) {
	rows, err := d.Orgs.GetMembers(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, len(rows))
	for _, m := range rows {
		out = append(out, Member{UserID: m.UserID, Email: m.Email, OrgRole: m.Role})
	}
	return out, nil
}

func (d DomainDirectory) Access(ctx context.Context, orgID, projectID uuid.UUID) (string, map[uuid.UUID]string, error) {
	explicit := map[uuid.UUID]string{}
	if d.Roles == nil {
		return authz.ModeOpen, explicit, nil
	}
	mode, err := d.Roles.GetOrgAccessMode(ctx, orgID)
	if err != nil {
		return "", nil, err
	}
	rows, err := d.Roles.ListExplicit(ctx, projectID)
	if err != nil {
		return "", nil, err
	}
	for _, m := range rows {
		explicit[m.UserID] = m.Role
	}
	return mode, explicit, nil
}

func splitRepoURL(raw string) (owner, repo string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", false
	}
	parts := strings.Split(strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
