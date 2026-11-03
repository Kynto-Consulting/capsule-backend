package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitimport"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// Git Capsule C1: importing repositories from GitHub (importCreate, importGet) and the push mirror
// (mirrorGet, mirrorPut, mirrorDelete, mirrorSync, in git_mirror.go). Contract:
// docs/git-capsule/API.openapi.yaml.
//
// The GitHub token travels in the body of importCreate only. These handlers never log a body, never
// echo the token and mark the response no-store.

// GitImportWiring is what WireGitImport needs from main.go.
type GitImportWiring struct {
	Import *gitimport.Service
	Mirror *gitimport.MirrorService
	Logger *slog.Logger
}

var (
	gitImportMu     sync.RWMutex
	gitImportShared *GitImportWiring
)

// WireGitImport publishes the C1 services for MountGitImport. Called from the git-capsule:wiring block.
func WireGitImport(w GitImportWiring) {
	gitImportMu.Lock()
	gitImportShared = &w
	gitImportMu.Unlock()
}

func sharedGitImport() *GitImportWiring {
	gitImportMu.RLock()
	defer gitImportMu.RUnlock()
	return gitImportShared
}

// GitImportDeps is what MountGitImport takes from the router.
type GitImportDeps struct {
	Authz    *authz.Service
	Orgs     domain.OrganizationRepository
	Projects domain.ProjectRepository
}

type gitImportAPI struct {
	authzHolder
	d  GitImportDeps
	w  *GitImportWiring
	lg *slog.Logger
}

// MountGitImport registers the C1 routes inside the authenticated /api/v1 group. It does nothing until
// WireGitImport ran.
func MountGitImport(r chi.Router, d GitImportDeps) {
	w := sharedGitImport()
	if w == nil {
		return
	}
	a := &gitImportAPI{d: d, w: w, lg: w.Logger}
	if a.lg == nil {
		a.lg = slog.Default()
	}
	a.svc = d.Authz
	if w.Import != nil {
		r.Post("/orgs/{orgID}/git/imports", a.importCreate)
		r.Get("/orgs/{orgID}/git/imports/{importID}", a.importGet)
	}
	if w.Mirror != nil {
		const p = "/orgs/{orgID}/projects/{projectID}/git/mirror"
		r.Get(p, a.mirrorGet)
		r.Put(p, a.mirrorPut)
		r.Delete(p, a.mirrorDelete)
		r.Post(p+"/sync", a.mirrorSync)
	}
}

// ---- import ---------------------------------------------------------------------------------

type importRequest struct {
	Source         string   `json:"source"`
	Token          string   `json:"token"`
	Repos          []string `json:"repos"`
	TargetOrgID    string   `json:"target_org_id"`
	CreateProjects *bool    `json:"create_projects"`
	Include        []string `json:"include"`
}

type importRepoJSON struct {
	Name       string                      `json:"name"`
	Status     string                      `json:"status"`
	ProjectID  *uuid.UUID                  `json:"project_id"`
	Error      string                      `json:"error"`
	Warnings   []string                    `json:"warnings"`
	CodeOwners *gitimport.CodeOwnersReport `json:"codeowners,omitempty"`
}

type importJobJSON struct {
	ID         uuid.UUID        `json:"id"`
	Status     string           `json:"status"`
	Attempt    int              `json:"attempt"`
	Resumed    bool             `json:"resumed,omitempty"`
	Repos      []importRepoJSON `json:"repos"`
	CreatedAt  time.Time        `json:"created_at"`
	UpdatedAt  time.Time        `json:"updated_at"`
	FinishedAt *time.Time       `json:"finished_at"`
}

func importJob(im *gitimport.Import, resumed bool) importJobJSON {
	j := importJobJSON{ID: im.ID, Status: im.Status, Attempt: im.Attempts, Resumed: resumed, Repos: make([]importRepoJSON, 0, len(im.Repos)),
		CreatedAt: im.CreatedAt, UpdatedAt: im.UpdatedAt, FinishedAt: im.FinishedAt}
	for _, r := range im.Repos {
		w := r.Warnings
		if w == nil {
			w = []string{}
		}
		j.Repos = append(j.Repos, importRepoJSON{Name: r.Name, Status: r.Status, ProjectID: r.ProjectID, Error: r.Error, Warnings: w, CodeOwners: r.CodeOwners})
	}
	return j
}

// orgAdmin authorizes org.admin on the org of the URL and returns its id.
func (a *gitImportAPI) orgAdmin(w http.ResponseWriter, r *http.Request) (*domain.User, uuid.UUID, bool) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return nil, uuid.Nil, false
	}
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return nil, uuid.Nil, false
	}
	role, err := a.d.Orgs.GetMemberRole(r.Context(), orgID, user.ID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && role == "") {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return nil, uuid.Nil, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check permissions")
		return nil, uuid.Nil, false
	}
	if !isOrgAdmin(role) {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "organization admin role required")
		return nil, uuid.Nil, false
	}
	return user, orgID, true
}

func importNoStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// decodeBody reads a bounded JSON body rejecting unknown fields and trailing data. It never logs it.
func importDecodeBody(w http.ResponseWriter, r *http.Request, max int64, dst any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		respondError(w, http.StatusRequestEntityTooLarge, "TOO_LARGE", "request body too large")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil || dec.More() {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return false
	}
	return true
}

func (a *gitImportAPI) importCreate(w http.ResponseWriter, r *http.Request) {
	importNoStore(w)
	user, orgID, ok := a.orgAdmin(w, r)
	if !ok {
		return
	}
	var req importRequest
	if !importDecodeBody(w, r, 64<<10, &req) {
		return
	}
	if req.Source != "github" {
		badRequest(w, "source must be github")
		return
	}
	if req.TargetOrgID != "" {
		if id, err := uuid.Parse(req.TargetOrgID); err != nil || id != orgID {
			badRequest(w, "target_org_id must be the organization of the URL")
			return
		}
	}
	idem := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if len(idem) > 128 {
		badRequest(w, "Idempotency-Key is longer than 128 characters")
		return
	}
	org, err := a.d.Orgs.GetByID(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "organization not found")
		return
	}
	create := true
	if req.CreateProjects != nil {
		create = *req.CreateProjects
	}
	im, resumed, err := a.w.Import.Start(r.Context(), gitimport.StartInput{
		OrgID: orgID, OrgSlug: org.Slug, UserID: user.ID, IP: middleware.ClientIP(r), Token: req.Token,
		Repos: req.Repos, Include: req.Include, CreateProjects: create, IdemKey: idem,
	})
	req.Token = "" // drop our reference; the service goroutine holds the only other one
	if err != nil {
		a.importFail(w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, importJob(im, resumed))
}

func (a *gitImportAPI) importFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, gitimport.ErrValidation):
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
	case errors.Is(err, gitimport.ErrBadToken):
		respondError(w, http.StatusUnprocessableEntity, "TOKEN_INVALID", "the GitHub token was rejected; check that it is valid and can read the repositories")
	case errors.Is(err, gitimport.ErrIdempotencyConflict):
		respondError(w, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "that Idempotency-Key belongs to a different or still running import")
	case errors.Is(err, gitimport.ErrSlugBusy):
		respondError(w, http.StatusConflict, "CONFLICT", "another import is already using one of those repository names")
	case errors.Is(err, gitimport.ErrNotConfigured):
		respondError(w, http.StatusServiceUnavailable, "GIT_NOT_READY", "the Git service is not configured on this server")
	default:
		a.lg.Warn("git import: request failed", "error", gitimport.Redact(err.Error()))
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
	}
}

func (a *gitImportAPI) importGet(w http.ResponseWriter, r *http.Request) {
	_, orgID, ok := a.orgAdmin(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "importID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid import id")
		return
	}
	im, err := a.w.Import.Get(r.Context(), orgID, id)
	if errors.Is(err, domain.ErrNotFound) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "import not found")
		return
	}
	if err != nil {
		a.lg.Warn("git import: loading failed", "error", gitimport.Redact(err.Error()))
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		return
	}
	respondJSON(w, http.StatusOK, importJob(im, false))
}

// ---- shared with git_mirror.go --------------------------------------------------------------

// gitcoreFail writes a gitcore error of a mirror call.
func (a *gitImportAPI) gitcoreFail(w http.ResponseWriter, err error) bool {
	e, ok := gitcore.AsError(err)
	if !ok {
		return false
	}
	switch e.Code {
	case gitcore.CodeNotFound:
		respondError(w, http.StatusConflict, "GIT_NOT_READY", "the project has no repository in the Git service yet")
	case gitcore.CodeUnprocessed:
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", gitimport.Redact(e.Message))
	case gitcore.CodeNotReady:
		w.Header().Set("Retry-After", "5")
		respondError(w, http.StatusServiceUnavailable, "GIT_NOT_READY", "the Git service is not available right now")
	default:
		respondError(w, http.StatusBadGateway, "UPSTREAM_GIT_ERROR", gitimport.Redact(e.Message))
	}
	return true
}
