package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type errorBody struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Hint    string         `json:"hint,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr writes a typed error, or a generic 500 for anything else (the cause is logged, never returned: it could carry
// internal detail).
func writeErr(w http.ResponseWriter, logger *slog.Logger, err error) {
	if e, ok := asError(err); ok {
		writeJSON(w, e.Status, map[string]any{"error": errorBody{Code: e.Code, Message: e.Message, Hint: e.Hint, Details: e.Details}})
		return
	}
	if logger != nil {
		logger.Error("gateway: request failed", "error", err.Error())
	}
	writeJSON(w, http.StatusInternalServerError, map[string]any{"error": errorBody{Code: "internal", Message: "internal error"}})
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(dst); err != nil {
		writeErr(w, nil, errBadRequest("invalid request body"))
		return false
	}
	return true
}

// MountAPI registers the user API inside the authenticated /api/v1 group. Paths follow the rest of the API
// (/orgs/{orgID}/projects/{projectID}/...), so every call carries the organisation that authz needs.
func (s *Service) MountAPI(r chi.Router) {
	base := "/orgs/{orgID}/projects/{projectID}/gateway"
	r.Get(base+"/services", s.handleListServices)
	r.Post(base+"/services", s.handleCreateService)
	r.Patch(base+"/services/{service}", s.handleUpdateService)
	r.Delete(base+"/services/{service}", s.handleDeleteService)
	r.Get(base+"/services/{service}/connection-info", s.handleConnectionInfo)
	r.Post(base+"/services/{service}/connection-token", s.handleConnectionToken)
	r.Post(base+"/services/{service}/port", s.handlePortLease)
	r.Delete(base+"/services/{service}/port", s.handlePortRelease)
	r.Get(base+"/service-tokens", s.handleListServiceTokens)
	r.Post(base+"/service-tokens", s.handleCreateServiceToken)
	r.Delete(base+"/service-tokens/{tokenID}", s.handleRevokeServiceToken)
	r.Get("/orgs/{orgID}/gateway/policy", s.handlePolicyGet)
	r.Put("/orgs/{orgID}/gateway/policy", s.handlePolicySet)
}

// begin authenticates the user, enforces act on the project (authz: never the org role alone) and loads the project.
//   - not an org member: 403; member who must not see the project: 404; visible but role too low: 403
//   - project of another organisation: 404
func (s *Service) begin(w http.ResponseWriter, r *http.Request, act authz.Action) (*domain.Project, Actor, bool) {
	w.Header().Set("Cache-Control", "no-store")
	user := middleware.GetUser(r.Context())
	if user == nil {
		writeErr(w, s.log, &Error{Status: 401, Code: "unauthorized", Message: "not authenticated"})
		return nil, Actor{}, false
	}
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		writeErr(w, s.log, errBadRequest("invalid organization id"))
		return nil, Actor{}, false
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		writeErr(w, s.log, errBadRequest("invalid project id"))
		return nil, Actor{}, false
	}
	acc, err := s.d.Authz.Access(r.Context(), user.ID, orgID, projectID)
	if err != nil {
		writeErr(w, s.log, err)
		return nil, Actor{}, false
	}
	switch {
	case !acc.Member:
		writeErr(w, s.log, errForbidden("not a member"))
		return nil, Actor{}, false
	case acc.Hidden:
		writeErr(w, s.log, errNotFound())
		return nil, Actor{}, false
	case !authz.RoleAllows(acc.Role, act):
		writeErr(w, s.log, errForbidden("your project role does not allow this action"))
		return nil, Actor{}, false
	}
	p, err := s.d.Projects.GetByID(r.Context(), projectID)
	if err != nil || p == nil || p.OrgID != orgID {
		writeErr(w, s.log, errNotFound())
		return nil, Actor{}, false
	}
	return p, Actor{UserID: user.ID, IP: middleware.ClientIP(r)}, true
}

func (s *Service) handleListServices(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.begin(w, r, authz.ProjectRead)
	if !ok {
		return
	}
	out, err := s.ListServices(r.Context(), p)
	if err != nil {
		writeErr(w, s.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": out})
}

func (s *Service) handleCreateService(w http.ResponseWriter, r *http.Request) {
	p, a, ok := s.begin(w, r, authz.ProjectNetwork)
	if !ok {
		return
	}
	var in CreateInput
	if !decodeBody(w, r, &in) {
		return
	}
	out, err := s.CreateService(r.Context(), p, a, in)
	if err != nil {
		writeErr(w, s.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Service) handleUpdateService(w http.ResponseWriter, r *http.Request) {
	p, a, ok := s.begin(w, r, authz.ProjectNetwork)
	if !ok {
		return
	}
	var in UpdateInput
	if !decodeBody(w, r, &in) {
		return
	}
	out, err := s.UpdateService(r.Context(), p, a, chi.URLParam(r, "service"), in)
	if err != nil {
		writeErr(w, s.log, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handleDeleteService(w http.ResponseWriter, r *http.Request) {
	p, a, ok := s.begin(w, r, authz.ProjectNetwork)
	if !ok {
		return
	}
	if err := s.DeleteService(r.Context(), p, a, chi.URLParam(r, "service")); err != nil {
		writeErr(w, s.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleConnectionInfo(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.begin(w, r, authz.ProjectRead)
	if !ok {
		return
	}
	out, err := s.ConnectionInfo(r.Context(), p, chi.URLParam(r, "service"))
	if err != nil {
		writeErr(w, s.log, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handleConnectionToken(w http.ResponseWriter, r *http.Request) {
	p, a, ok := s.begin(w, r, authz.ProjectConnect)
	if !ok {
		return
	}
	out, err := s.IssueConnectionToken(r.Context(), p, a, chi.URLParam(r, "service"))
	if err != nil {
		writeErr(w, s.log, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handlePortLease(w http.ResponseWriter, r *http.Request) {
	p, a, ok := s.begin(w, r, authz.ProjectNetwork)
	if !ok {
		return
	}
	out, err := s.LeasePort(r.Context(), p, a, chi.URLParam(r, "service"))
	if err != nil {
		writeErr(w, s.log, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handlePortRelease(w http.ResponseWriter, r *http.Request) {
	p, a, ok := s.begin(w, r, authz.ProjectNetwork)
	if !ok {
		return
	}
	if err := s.ReleasePort(r.Context(), p, a, chi.URLParam(r, "service")); err != nil {
		writeErr(w, s.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleListServiceTokens(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.begin(w, r, authz.ProjectNetwork)
	if !ok {
		return
	}
	out, err := s.ListServiceTokens(r.Context(), p)
	if err != nil {
		writeErr(w, s.log, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": out})
}

func (s *Service) handleCreateServiceToken(w http.ResponseWriter, r *http.Request) {
	p, a, ok := s.begin(w, r, authz.ProjectNetwork)
	if !ok {
		return
	}
	var in ServiceTokenInput
	if !decodeBody(w, r, &in) {
		return
	}
	out, err := s.CreateServiceToken(r.Context(), p, a, in)
	if err != nil {
		writeErr(w, s.log, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Service) handleRevokeServiceToken(w http.ResponseWriter, r *http.Request) {
	p, a, ok := s.begin(w, r, authz.ProjectNetwork)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		writeErr(w, s.log, errBadRequest("invalid token id"))
		return
	}
	if err := s.RevokeServiceToken(r.Context(), p, a, id); err != nil {
		writeErr(w, s.log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// orgRole authenticates and returns the caller's organisation role ("" + false after writing the error).
func (s *Service) orgRole(w http.ResponseWriter, r *http.Request) (uuid.UUID, Actor, string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	user := middleware.GetUser(r.Context())
	if user == nil {
		writeErr(w, s.log, &Error{Status: 401, Code: "unauthorized", Message: "not authenticated"})
		return uuid.Nil, Actor{}, "", false
	}
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		writeErr(w, s.log, errBadRequest("invalid organization id"))
		return uuid.Nil, Actor{}, "", false
	}
	role, err := s.d.Orgs.GetMemberRole(r.Context(), orgID, user.ID)
	if err != nil || role == "" {
		writeErr(w, s.log, errForbidden("not a member"))
		return uuid.Nil, Actor{}, "", false
	}
	return orgID, Actor{UserID: user.ID, IP: middleware.ClientIP(r)}, role, true
}

func (s *Service) handlePolicyGet(w http.ResponseWriter, r *http.Request) {
	orgID, _, _, ok := s.orgRole(w, r)
	if !ok {
		return
	}
	out, err := s.OrgPolicy(r.Context(), orgID)
	if err != nil {
		writeErr(w, s.log, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handlePolicySet(w http.ResponseWriter, r *http.Request) {
	orgID, a, role, ok := s.orgRole(w, r)
	if !ok {
		return
	}
	if role != "owner" && role != "admin" {
		writeErr(w, s.log, errForbidden("only organization owners and admins can change the policy"))
		return
	}
	var in struct {
		GatewayPolicy string `json:"gateway_policy"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	out, err := s.SetOrgPolicy(r.Context(), orgID, a, in.GatewayPolicy)
	if err != nil {
		writeErr(w, s.log, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
