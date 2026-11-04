package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/access"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// Permission-management API (docs/permissions/API.openapi.yaml: templates, groups, assignments, /me/permissions, simulator, audit).
// The handlers only translate HTTP: every rule lives in internal/access. WireAccess publishes the service; MountAccess registers the
// routes inside the authenticated /api/v1 group and does nothing until WireAccess ran (same pattern as WireGitTokens).

var (
	accessMu  sync.RWMutex
	accessSvc *access.Service
	accessLog *slog.Logger
)

// WireAccess publishes the access service for MountAccess. A nil service leaves the routes unmounted.
func WireAccess(svc *access.Service, log *slog.Logger) {
	accessMu.Lock()
	accessSvc, accessLog = svc, log
	accessMu.Unlock()
}

// maxAccessBody caps every JSON body of this API (a template has at most 200 permissions, an invitation 20 assignments).
const maxAccessBody = 1 << 20

type accessAPI struct {
	svc *access.Service
	log *slog.Logger
}

func sharedAccess() *accessAPI {
	accessMu.RLock()
	defer accessMu.RUnlock()
	if accessSvc == nil {
		return nil
	}
	l := accessLog
	if l == nil {
		l = slog.Default()
	}
	return &accessAPI{svc: accessSvc, log: l}
}

// MountAccess registers the permission-management routes in the authenticated /api/v1 group.
func MountAccess(r chi.Router) {
	h := sharedAccess()
	if h == nil {
		return
	}
	r.Get("/permissions/catalog", h.catalog)
	r.Get("/me/permissions", h.me)
	r.Get("/me/permissions/explain", h.meExplain)

	r.Get("/orgs/{orgID}/templates", h.templatesList)
	r.Post("/orgs/{orgID}/templates", h.templatesCreate)
	r.Get("/orgs/{orgID}/templates/{templateID}", h.templatesGet)
	r.Put("/orgs/{orgID}/templates/{templateID}", h.templatesPublish)
	r.Delete("/orgs/{orgID}/templates/{templateID}", h.templatesDelete)
	r.Get("/orgs/{orgID}/templates/{templateID}/versions", h.templatesVersions)
	r.Get("/orgs/{orgID}/templates/{templateID}/versions/{from}/diff/{to}", h.templatesDiff)

	r.Get("/orgs/{orgID}/groups", h.groupsList)
	r.Post("/orgs/{orgID}/groups", h.groupsCreate)
	r.Get("/orgs/{orgID}/groups/{groupID}", h.groupsGet)
	r.Patch("/orgs/{orgID}/groups/{groupID}", h.groupsUpdate)
	r.Delete("/orgs/{orgID}/groups/{groupID}", h.groupsArchive)
	r.Get("/orgs/{orgID}/groups/{groupID}/members", h.groupMembersList)
	r.Post("/orgs/{orgID}/groups/{groupID}/members", h.groupMembersAdd)
	r.Delete("/orgs/{orgID}/groups/{groupID}/members/{userID}", h.groupMembersRemove)

	r.Get("/orgs/{orgID}/assignments", h.assignmentsList)
	r.Post("/orgs/{orgID}/assignments", h.assignmentsCreate)
	r.Get("/orgs/{orgID}/assignments/{assignmentID}", h.assignmentsGet)
	r.Patch("/orgs/{orgID}/assignments/{assignmentID}", h.assignmentsPatch)
	r.Delete("/orgs/{orgID}/assignments/{assignmentID}", h.assignmentsRevoke)
	r.Get("/orgs/{orgID}/projects/{projectID}/access", h.projectAccess)
	r.Put("/orgs/{orgID}/projects/{projectID}/access-override", h.accessOverride)
	r.Get("/orgs/{orgID}/users/{userID}/permissions", h.userPermissions)
	r.Post("/orgs/{orgID}/access/simulate", h.simulate)
	r.Put("/orgs/{orgID}/members/{userID}/template", h.memberTemplate)
	r.Get("/orgs/{orgID}/access-audit", h.accessAudit)
}

// ---------------------------------------------------------------- helpers

type accessErrorBody struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

func (h *accessAPI) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *access.Error
	if errors.As(err, &ae) {
		respondJSON(w, ae.Status, struct {
			Error accessErrorBody `json:"error"`
		}{accessErrorBody{Code: ae.Code, Message: ae.Message, Details: ae.Details}})
		return
	}
	if r.Context().Err() == nil {
		h.log.Error("access api", "path", r.URL.Path, "error", err)
	}
	respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
}

// actor builds the audit identity of the request. The user is always the authenticated one; the organization comes from the path.
func (h *accessAPI) actor(w http.ResponseWriter, r *http.Request) (access.Actor, bool) {
	u := middleware.GetUser(r.Context())
	if u == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return access.Actor{}, false
	}
	a := access.Actor{UserID: u.ID, UserAgent: r.UserAgent(), RequestID: middleware.GetRequestID(r.Context()), Via: "session"}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		a.IP = host
	} else {
		a.IP = r.RemoteAddr
	}
	if ti, ok := middleware.GetTokenInfo(r.Context()); ok && ti.TokenID != uuid.Nil {
		id := ti.TokenID
		a.Via, a.TokenID = "token", &id
	}
	return a, true
}

func pathUUID(w http.ResponseWriter, r *http.Request, name, what string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, name))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid "+what+" id")
		return uuid.Nil, false
	}
	return id, true
}

// begin returns the actor and the organization of the path.
func (h *accessAPI) begin(w http.ResponseWriter, r *http.Request) (access.Actor, uuid.UUID, bool) {
	a, ok := h.actor(w, r)
	if !ok {
		return a, uuid.Nil, false
	}
	org, ok := pathUUID(w, r, "orgID", "organization")
	return a, org, ok
}

// readBody reads and decodes a JSON body of at most 1 MiB. It returns the raw bytes for the idempotency fingerprint.
func readAccessBody(w http.ResponseWriter, r *http.Request, v any) ([]byte, bool) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAccessBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			respondError(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "the request body is larger than 1 MiB")
			return nil, false
		}
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "could not read the request body")
		return nil, false
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "a JSON body is required")
		return nil, false
	}
	if err := json.Unmarshal(raw, v); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "the request body is not valid JSON for this operation")
		return nil, false
	}
	return raw, true
}

// idem returns the Idempotency-Key of the request fingerprinted with its method, URI and body (nil without the header).
func idemOf(r *http.Request, body []byte) *access.Idem {
	k := r.Header.Get("Idempotency-Key")
	if k == "" {
		return nil
	}
	return &access.Idem{Key: k, Hash: access.HashRequest(r.Method, r.URL.RequestURI(), body)}
}

// write sends the outcome of an idempotent write.
func writeReply[T any](w http.ResponseWriter, rep access.Reply[T]) {
	if rep.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	if rep.Status == http.StatusNoContent {
		respondNoContent(w)
		return
	}
	respondJSON(w, rep.Status, rep.Value)
}
