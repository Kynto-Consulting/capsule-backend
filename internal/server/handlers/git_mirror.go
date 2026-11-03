package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitimport"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// Push mirror routes (mirrorGet / mirrorPut / mirrorDelete / mirrorSync). T17: the code of a private
// project leaves to a third party, so every route needs git.admin (authz, not the org role) and every
// change is audited; the response carries `notice`, which the UI must show.

type mirrorRequest struct {
	RemoteURL  string   `json:"remote_url"`
	Credential *string  `json:"credential"`
	Branches   []string `json:"branches"`
	Interval   string   `json:"interval"`
}

type mirrorJSON struct {
	RemoteURL     string     `json:"remote_url"`
	Branches      []string   `json:"branches"`
	Interval      string     `json:"interval"`
	LastSyncAt    *time.Time `json:"last_sync_at"`
	LastError     string     `json:"last_error"`
	HasCredential bool       `json:"has_credential"`
	RemoteHost    string     `json:"remote_host"`
	Syncing       bool       `json:"syncing"`
	Notice        string     `json:"notice"`
}

func mirrorBody(v *gitimport.MirrorView) mirrorJSON {
	return mirrorJSON{RemoteURL: v.RemoteURL, Branches: v.Branches, Interval: v.Interval, LastSyncAt: v.LastSyncAt, LastError: v.LastError,
		HasCredential: v.HasCredential, RemoteHost: v.RemoteHost, Syncing: v.Syncing, Notice: v.Notice}
}

// mirrorScope authorizes git.admin on the project of the URL (403 not a member / role too low, 404 hidden).
func (a *gitImportAPI) mirrorScope(w http.ResponseWriter, r *http.Request) (gitimport.Target, gitimport.Actor, bool) {
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return gitimport.Target{}, gitimport.Actor{}, false
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return gitimport.Target{}, gitimport.Actor{}, false
	}
	if !a.authorize(w, r, a.d.Orgs, orgID, projectID, authz.GitAdmin) {
		return gitimport.Target{}, gitimport.Actor{}, false
	}
	p, err := a.d.Projects.GetByID(r.Context(), projectID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && p.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return gitimport.Target{}, gitimport.Actor{}, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load project")
		return gitimport.Target{}, gitimport.Actor{}, false
	}
	org, err := a.d.Orgs.GetByID(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "organization not found")
		return gitimport.Target{}, gitimport.Actor{}, false
	}
	t := gitimport.Target{OrgID: orgID, ProjectID: projectID, Repo: gitcore.RepoRef{Owner: org.Slug, Repo: p.Slug}}
	actor := gitimport.Actor{IP: middleware.ClientIP(r)}
	if u := middleware.GetUser(r.Context()); u != nil {
		actor.UserID = u.ID
	}
	return t, actor, true
}

func (a *gitImportAPI) mirrorFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, gitimport.ErrValidation):
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
	case errors.Is(err, domain.ErrNotFound):
		respondError(w, http.StatusNotFound, "NOT_FOUND", "this project has no mirror")
	case errors.Is(err, gitimport.ErrBusy):
		respondError(w, http.StatusConflict, "CONFLICT", "a synchronization is already running")
	case errors.Is(err, gitimport.ErrNotConfigured):
		respondError(w, http.StatusServiceUnavailable, "GIT_NOT_READY", "the Git service is not configured on this server")
	case a.gitcoreFail(w, err):
	default:
		a.lg.Warn("git mirror: request failed", "error", gitimport.Redact(err.Error()))
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
	}
}

func (a *gitImportAPI) mirrorGet(w http.ResponseWriter, r *http.Request) {
	t, _, ok := a.mirrorScope(w, r)
	if !ok {
		return
	}
	v, err := a.w.Mirror.Get(r.Context(), t)
	if err != nil {
		a.mirrorFail(w, err)
		return
	}
	importNoStore(w)
	respondJSON(w, http.StatusOK, mirrorBody(v))
}

func (a *gitImportAPI) mirrorPut(w http.ResponseWriter, r *http.Request) {
	importNoStore(w)
	t, actor, ok := a.mirrorScope(w, r)
	if !ok {
		return
	}
	var req mirrorRequest
	if !importDecodeBody(w, r, 32<<10, &req) {
		return
	}
	v, err := a.w.Mirror.Put(r.Context(), t, actor, gitimport.MirrorInput{RemoteURL: req.RemoteURL, Credential: req.Credential, Branches: req.Branches, Interval: req.Interval})
	req.Credential = nil
	if err != nil {
		a.mirrorFail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, mirrorBody(v))
}

func (a *gitImportAPI) mirrorDelete(w http.ResponseWriter, r *http.Request) {
	t, actor, ok := a.mirrorScope(w, r)
	if !ok {
		return
	}
	if err := a.w.Mirror.Delete(r.Context(), t, actor); err != nil {
		a.mirrorFail(w, err)
		return
	}
	respondNoContent(w)
}

func (a *gitImportAPI) mirrorSync(w http.ResponseWriter, r *http.Request) {
	t, actor, ok := a.mirrorScope(w, r)
	if !ok {
		return
	}
	job, err := a.w.Mirror.Sync(r.Context(), t, actor)
	if err != nil {
		a.mirrorFail(w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{"id": job.ID, "status": job.Status, "detail": job.Detail})
}
