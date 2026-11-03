package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/recovery"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// RecoverService is what the handlers need from recovery.Service (faked in tests).
type RecoverService interface {
	Enabled() bool
	Plan(ctx context.Context, req recovery.Request) (recovery.Plan, error)
	Start(ctx context.Context, req recovery.Request, user *uuid.UUID, idemKey string) (*recovery.Run, error)
	Get(ctx context.Context, id uuid.UUID) (*recovery.Run, error)
}

// RecoverHandler serves gitRecoverPlatform, gitRecoverGet and recoverProject (DR-BACKUP.md section 3).
type RecoverHandler struct {
	authzHolder
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
	svc      RecoverService
}

func NewRecoverHandler(orgs domain.OrganizationRepository, projects domain.ProjectRepository, svc RecoverService) *RecoverHandler {
	return &RecoverHandler{orgs: orgs, projects: projects, svc: svc}
}

// MountRecover registers the recovery routes inside the authenticated /api/v1 group. The service is
// the one published by recovery.WireRecovery (nil when disabled: the routes answer 409 RECOVERY_DISABLED).
func MountRecover(r chi.Router, az *authz.Service, orgs domain.OrganizationRepository, projects domain.ProjectRepository) {
	var svc RecoverService
	if s := recovery.Shared(); s != nil {
		svc = s
	}
	h := NewRecoverHandler(orgs, projects, svc)
	h.SetAuthz(az)
	h.Mount(r)
}

// Mount registers the three routes on r.
func (h *RecoverHandler) Mount(r chi.Router) {
	r.Post("/git/admin/recover", h.Platform)
	r.Get("/git/admin/recover/{runID}", h.Get)
	r.Post("/orgs/{orgID}/projects/{projectID}/recover", h.Project)
}

type recoverBody struct {
	Mode       string     `json:"mode"`
	SnapshotID *uuid.UUID `json:"snapshot_id"`
	Target     string     `json:"target"`
	Scope      []string   `json:"scope"`
	At         *time.Time `json:"point_in_time"`
	Force      bool       `json:"force_overwrite"`
	Continue   bool       `json:"continue_on_error"`
}

type recoverStepView struct {
	Name       string     `json:"name"`
	Phase      string     `json:"phase,omitempty"`
	Status     string     `json:"status"`
	Detail     string     `json:"detail"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

type recoverRunView struct {
	ID        string            `json:"id"`
	Mode      string            `json:"mode"`
	Status    string            `json:"status"`
	Steps     []recoverStepView `json:"steps"`
	ReportURL string            `json:"report_url,omitempty"`
	PlanID    string            `json:"plan_id,omitempty"`
	Ready     *bool             `json:"ready,omitempty"`
	EstimateS *int              `json:"estimate_seconds,omitempty"`
	Risks     []recovery.Risk   `json:"risks,omitempty"`
}

func viewOfRun(r *recovery.Run) recoverRunView {
	v := recoverRunView{ID: r.ID.String(), Mode: string(r.Mode), Status: string(r.Status), ReportURL: r.ReportURL, PlanID: r.PlanID, Steps: []recoverStepView{}}
	for _, s := range r.Steps {
		v.Steps = append(v.Steps, recoverStepView{Name: s.Name, Phase: s.Phase, Status: string(s.Status), Detail: s.Detail, StartedAt: s.StartedAt, FinishedAt: s.FinishedAt})
	}
	return v
}

func viewOfPlan(p recovery.Plan) recoverRunView {
	v := recoverRunView{ID: uuid.Nil.String(), Mode: string(recovery.ModePlan), Status: string(recovery.RunPlanned), PlanID: p.PlanID, Steps: []recoverStepView{}, Risks: p.Risks}
	ready, est := p.Ready, p.EstimateSecond
	v.Ready, v.EstimateS = &ready, &est
	for _, s := range p.Steps {
		v.Steps = append(v.Steps, recoverStepView{Name: s.Name, Phase: s.Phase, Status: string(recovery.StepPending)})
	}
	return v
}

func (h *RecoverHandler) recoverError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, recovery.ErrInvalid):
		respondError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
	case errors.Is(err, recovery.ErrNotFound):
		respondError(w, http.StatusNotFound, "NOT_FOUND", "not found")
	case errors.Is(err, recovery.ErrActive):
		respondError(w, http.StatusConflict, "RECOVERY_IN_PROGRESS", "another recovery is already running")
	case errors.Is(err, recovery.ErrBlocked):
		respondError(w, http.StatusUnprocessableEntity, "POLICY_BLOCKED", "the plan has blocking risks: run mode=plan, fix them or retry with the explicit override")
	case errors.Is(err, recovery.ErrPlanChanged):
		respondError(w, http.StatusConflict, "PLAN_CHANGED", err.Error())
	default:
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "recovery operation failed")
	}
}

func (h *RecoverHandler) decode(w http.ResponseWriter, r *http.Request, all bool, project *uuid.UUID) (recovery.Request, bool) {
	var b recoverBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&b); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return recovery.Request{}, false
	}
	req := recovery.Request{Mode: recovery.Mode(b.Mode), All: all, ProjectID: project, SnapshotID: b.SnapshotID,
		Target: recovery.Target(b.Target), At: b.At, ForceOverwrite: b.Force, ContinueOnErr: b.Continue}
	for _, s := range b.Scope {
		req.Scopes = append(req.Scopes, recovery.Scope(s))
	}
	return req, true
}

func (h *RecoverHandler) enabled(w http.ResponseWriter) bool {
	if h.svc == nil || !h.svc.Enabled() {
		respondError(w, http.StatusConflict, "RECOVERY_DISABLED", "recovery is disabled on this platform (CAPSULE_RECOVERY_ENABLED)")
		return false
	}
	return true
}

func (h *RecoverHandler) platformAdmin(w http.ResponseWriter, r *http.Request) bool {
	u := middleware.GetUser(r.Context())
	if u == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return false
	}
	if u.Role != "admin" {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "platform admin required")
		return false
	}
	return true
}

func (h *RecoverHandler) run(w http.ResponseWriter, r *http.Request, req recovery.Request) {
	if req.Mode == recovery.ModePlan {
		p, err := h.svc.Plan(r.Context(), req)
		if err != nil {
			h.recoverError(w, err)
			return
		}
		respondJSON(w, http.StatusAccepted, viewOfPlan(p))
		return
	}
	idem := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if len(idem) > 100 {
		respondError(w, http.StatusBadRequest, "INVALID_REQUEST", "Idempotency-Key too long")
		return
	}
	run, err := h.svc.Start(r.Context(), req, userPtr(r), idem)
	if err != nil {
		h.recoverError(w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, viewOfRun(run))
}

// POST /git/admin/recover (platform.admin)
func (h *RecoverHandler) Platform(w http.ResponseWriter, r *http.Request) {
	if !h.platformAdmin(w, r) || !h.enabled(w) {
		return
	}
	req, ok := h.decode(w, r, true, nil)
	if !ok {
		return
	}
	h.run(w, r, req)
}

// GET /git/admin/recover/{runID} (platform.admin)
func (h *RecoverHandler) Get(w http.ResponseWriter, r *http.Request) {
	if !h.platformAdmin(w, r) || !h.enabled(w) {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid run id")
		return
	}
	run, err := h.svc.Get(r.Context(), id)
	if err != nil {
		h.recoverError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, viewOfRun(run))
}

// POST /orgs/{orgID}/projects/{projectID}/recover (project.delete: it overwrites data)
func (h *RecoverHandler) Project(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}
	if !h.authorize(w, r, h.orgs, orgID, projectID, authz.ProjectDelete) {
		return
	}
	project, err := h.projects.GetByID(r.Context(), projectID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && project.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get project")
		return
	}
	if !h.enabled(w) {
		return
	}
	req, ok := h.decode(w, r, false, &projectID)
	if !ok {
		return
	}
	h.run(w, r, req)
}
