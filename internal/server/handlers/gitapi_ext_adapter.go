package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitprotect"
)

// gitcoreExtAdapter exposes gitcore.ActionsExt (gitcore types) as the gitapi optional interfaces
// (SecretLister, RunnerLister, ArtifactLister, RunRerunner), which are what the handlers and the
// contract rigs speak. gitapi cannot import types from gitcore's additions the other way round.
type gitcoreExtAdapter struct{ ax gitcore.ActionsExt }

func (g gitcoreExtAdapter) ListSecrets(ctx context.Context, r gitcore.RepoRef) ([]gitapi.SecretInfo, error) {
	l, err := g.ax.ListSecrets(ctx, r)
	if err != nil {
		return nil, err
	}
	out := make([]gitapi.SecretInfo, 0, len(l))
	for _, s := range l {
		out = append(out, gitapi.SecretInfo{Name: s.Name, UpdatedAt: s.UpdatedAt})
	}
	return out, nil
}

// ListRunners lists what the organization can use: its own runners plus the instance's (the
// runners are registered by Terraform/SSM at org or instance level, so they are "trusted"; a
// runner a repository registered on its own is not).
func (g gitcoreExtAdapter) ListRunners(ctx context.Context, org string) ([]gitapi.Runner, error) {
	l, err := g.ax.ListRunners(ctx, gitcore.RunnerScope{Owner: org, Visible: true})
	if err != nil {
		return nil, err
	}
	out := make([]gitapi.Runner, 0, len(l))
	for _, r := range l {
		out = append(out, gitapi.Runner{ID: strconv.FormatInt(r.ID, 10), Name: r.Name, Labels: r.Labels, Status: r.Status, Trusted: r.Scope != "repo"})
	}
	return out, nil
}

func (g gitcoreExtAdapter) ListArtifacts(ctx context.Context, r gitcore.RepoRef, runID int64) ([]gitapi.Artifact, error) {
	l, err := g.ax.ListArtifacts(ctx, r, runID)
	if err != nil {
		return nil, err
	}
	out := make([]gitapi.Artifact, 0, len(l))
	for _, a := range l {
		out = append(out, gitapi.Artifact{Name: a.Name, Size: a.Size, DownloadURL: a.DownloadURL, ExpiresAt: a.ExpiresAt})
	}
	return out, nil
}

func (g gitcoreExtAdapter) RerunRun(ctx context.Context, r gitcore.RepoRef, runID int64, failedOnly bool) (*gitcore.Run, error) {
	return g.ax.RerunRun(ctx, r, runID, failedOnly)
}

// extOf returns the optional capability T of core: the core itself when it implements T (rigs),
// otherwise the gitcore.ActionsExt adapter.
func extOf[T any](core gitcore.Core) (T, bool) {
	if v, ok := core.(T); ok {
		return v, true
	}
	if ax, ok := core.(gitcore.ActionsExt); ok {
		if v, ok := any(gitcoreExtAdapter{ax}).(T); ok {
			return v, true
		}
	}
	var zero T
	return zero, false
}

// failExt answers a capability gitcore knows Forgejo's API cannot offer (501 NOT_SUPPORTED with
// the reason) or any other gitcore error.
func (a *gitAPI) failExt(w http.ResponseWriter, err error) {
	if e, ok := gitcore.AsError(err); ok && e.Code == gitcore.CodeUnsupported {
		respondError(w, http.StatusNotImplemented, "NOT_SUPPORTED", e.Message)
		return
	}
	a.fail(w, err, false)
}

func (sc *gitScope) protectTarget() gitprotect.Target {
	return gitprotect.Target{ProjectID: sc.proj.ID, OrgID: sc.org.ID, OrgSlug: sc.org.Slug, ProjectSlug: sc.proj.Slug}
}

// failProtect maps a gitprotect policy error (POLICY_BLOCKED 422, PROTECTED_TAG 403...) with the
// same envelope as the A4 routes; gitcore errors keep their usual mapping.
func (a *gitAPI) failProtect(w http.ResponseWriter, err error) {
	if _, ok := gitcore.AsError(err); ok {
		a.fail(w, err, false)
		return
	}
	(&GitProtectHandler{}).fail(w, err)
}

// guardTag applies A4's protected-tag rule (403 PROTECTED_TAG without git.admin).
func (a *gitAPI) guardTag(w http.ResponseWriter, sc *gitScope, name, op string) bool {
	gp := gitprotect.Shared()
	if gp == nil || sc.user == nil {
		return true
	}
	admin, err := a.service(a.d.Orgs).Can(sc.ctx, sc.user.ID, sc.org.ID, sc.proj.ID, authz.GitAdmin)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check permissions")
		return false
	}
	if err := gp.GuardTag(name, admin, op); err != nil {
		a.failProtect(w, err)
		return false
	}
	return true
}

// tagRefused turns Forgejo's own tag-protection refusal (422 "protected tag") into PROTECTED_TAG.
func tagRefused(w http.ResponseWriter, err error) bool {
	if e, ok := gitcore.AsError(err); ok && e.Code == gitcore.CodeUnprocessed && strings.Contains(strings.ToLower(e.Message), "protected tag") {
		respondError(w, http.StatusForbidden, "PROTECTED_TAG", "the tag is protected: only a project administrator can change it")
		return true
	}
	return false
}
