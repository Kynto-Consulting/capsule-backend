package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/backup"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// BackupService is what the handlers need from backup.Service (faked in tests).
type BackupService interface {
	Enabled() bool
	Get(ctx context.Context, projectID uuid.UUID) (*backup.View, error)
	Update(ctx context.Context, projectID uuid.UUID, p backup.Patch) (*backup.View, error)
	StartBackup(ctx context.Context, projectID uuid.UUID, user *uuid.UUID) (uuid.UUID, error)
	StartVerify(ctx context.Context, projectID uuid.UUID, user *uuid.UUID) (uuid.UUID, error)
	StartRestore(ctx context.Context, projectID, snapshotID uuid.UUID, target string, user *uuid.UUID) (uuid.UUID, error)
	Snapshots(ctx context.Context, projectID uuid.UUID) ([]backup.SnapshotView, error)
	StartPlatformBackup(ctx context.Context, user *uuid.UUID) (uuid.UUID, error)
	StartPlatformVerify(ctx context.Context, user *uuid.UUID) (uuid.UUID, error)
	PlatformView(ctx context.Context) (map[string]any, error)
	Audit(ctx context.Context, e backup.AuditEntry)
}

// BackupHandler serves /orgs/{o}/projects/{p}/backups/* and /platform/backups/*.
type BackupHandler struct {
	authzHolder
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
	svc      BackupService
}

func NewBackupHandler(orgs domain.OrganizationRepository, projects domain.ProjectRepository, svc BackupService) *BackupHandler {
	return &BackupHandler{orgs: orgs, projects: projects, svc: svc}
}

func (h *BackupHandler) load(w http.ResponseWriter, r *http.Request, act authz.Action) (orgID, projectID uuid.UUID, ok bool) {
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	projectID, err = uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}
	if !h.authorize(w, r, h.orgs, orgID, projectID, act) {
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
	return orgID, projectID, true
}

// loadWrite additionally rejects with 409 BACKUPS_DISABLED when the platform flag is off.
func (h *BackupHandler) loadWrite(w http.ResponseWriter, r *http.Request, act authz.Action) (uuid.UUID, uuid.UUID, bool) {
	orgID, projectID, ok := h.load(w, r, act)
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	if !h.svc.Enabled() {
		backupsDisabled(w)
		return uuid.Nil, uuid.Nil, false
	}
	return orgID, projectID, true
}

func backupsDisabled(w http.ResponseWriter) {
	respondError(w, http.StatusConflict, "BACKUPS_DISABLED", "backups are disabled on this platform")
}

func backupError(w http.ResponseWriter, err error) {
	var inv *backup.InvalidError
	switch {
	case errors.Is(err, backup.ErrDisabled):
		backupsDisabled(w)
	case errors.Is(err, backup.ErrRunInProgress):
		respondError(w, http.StatusConflict, "BACKUP_IN_PROGRESS", "a backup job is already running for this project")
	case errors.Is(err, backup.ErrNotFound):
		respondError(w, http.StatusNotFound, "NOT_FOUND", "not found")
	case errors.As(err, &inv):
		respondError(w, http.StatusBadRequest, "INVALID_REQUEST", inv.Msg)
	default:
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "backup operation failed")
	}
}

func userPtr(r *http.Request) *uuid.UUID {
	if u := middleware.GetUser(r.Context()); u != nil {
		id := u.ID
		return &id
	}
	return nil
}

func (h *BackupHandler) audit(r *http.Request, orgID, projectID uuid.UUID, action string, vals map[string]any) {
	h.svc.Audit(context.WithoutCancel(r.Context()), backup.AuditEntry{OrgID: &orgID, UserID: userPtr(r), Action: action,
		ResourceType: "backup", ResourceID: &projectID, IP: middleware.ClientIP(r), NewValues: vals})
}

// GET .../backups
func (h *BackupHandler) Get(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.load(w, r, authz.ProjectRead)
	if !ok {
		return
	}
	v, err := h.svc.Get(r.Context(), projectID)
	if err != nil {
		backupError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, v)
}

// PUT .../backups  {enabled, schedule, retention_days, include:{databases, volumes}} (partial)
func (h *BackupHandler) Put(w http.ResponseWriter, r *http.Request) {
	orgID, projectID, ok := h.loadWrite(w, r, authz.ProjectOps)
	if !ok {
		return
	}
	var body struct {
		Enabled       *bool   `json:"enabled"`
		Schedule      *string `json:"schedule"`
		RetentionDays *int    `json:"retention_days"`
		Include       *struct {
			Databases *bool `json:"databases"`
			Volumes   *bool `json:"volumes"`
		} `json:"include"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	p := backup.Patch{Enabled: body.Enabled, Schedule: body.Schedule, RetentionDays: body.RetentionDays}
	if body.Include != nil {
		p.IncludeDatabases, p.IncludeVolumes = body.Include.Databases, body.Include.Volumes
	}
	v, err := h.svc.Update(r.Context(), projectID, p)
	if err != nil {
		backupError(w, err)
		return
	}
	h.audit(r, orgID, projectID, "backup.config_update", map[string]any{"enabled": v.Enabled, "schedule": v.Schedule,
		"retention_days": v.RetentionDays, "databases": v.Include.Databases, "volumes": v.Include.Volumes})
	respondJSON(w, http.StatusOK, v)
}

// POST .../backups/run -> 202 {"run_id"}
func (h *BackupHandler) Run(w http.ResponseWriter, r *http.Request) {
	orgID, projectID, ok := h.loadWrite(w, r, authz.ProjectOps)
	if !ok {
		return
	}
	id, err := h.svc.StartBackup(r.Context(), projectID, userPtr(r))
	if err != nil {
		backupError(w, err)
		return
	}
	h.audit(r, orgID, projectID, "backup.run", map[string]any{"run_id": id.String()})
	respondJSON(w, http.StatusAccepted, map[string]string{"run_id": id.String()})
}

// POST .../backups/verify -> 202 {"run_id"}
func (h *BackupHandler) Verify(w http.ResponseWriter, r *http.Request) {
	orgID, projectID, ok := h.loadWrite(w, r, authz.ProjectOps)
	if !ok {
		return
	}
	id, err := h.svc.StartVerify(r.Context(), projectID, userPtr(r))
	if err != nil {
		backupError(w, err)
		return
	}
	h.audit(r, orgID, projectID, "backup.verify", map[string]any{"run_id": id.String()})
	respondJSON(w, http.StatusAccepted, map[string]string{"run_id": id.String()})
}

// GET .../backups/snapshots -> {"data":[...]}
func (h *BackupHandler) Snapshots(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.load(w, r, authz.ProjectRead)
	if !ok {
		return
	}
	sn, err := h.svc.Snapshots(r.Context(), projectID)
	if err != nil {
		backupError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": sn})
}

// POST .../backups/restore {"snapshot_id","target"} -> 202 {"run_id"}. Needs ProjectDatabases.
// The API acts on an explicit request; the CLI and dashboard ask for double confirmation.
func (h *BackupHandler) Restore(w http.ResponseWriter, r *http.Request) {
	orgID, projectID, ok := h.loadWrite(w, r, authz.ProjectDatabases)
	if !ok {
		return
	}
	var body struct {
		SnapshotID string `json:"snapshot_id"`
		Target     string `json:"target"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	sid, err := uuid.Parse(body.SnapshotID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid snapshot_id")
		return
	}
	id, err := h.svc.StartRestore(r.Context(), projectID, sid, body.Target, userPtr(r))
	if err != nil {
		backupError(w, err)
		return
	}
	h.audit(r, orgID, projectID, "backup.restore", map[string]any{"run_id": id.String(), "snapshot_id": sid.String(), "target": body.Target})
	respondJSON(w, http.StatusAccepted, map[string]string{"run_id": id.String()})
}

// ── platform (platform admins only) ─────────────────────────────────────────

func (h *BackupHandler) platformAdmin(w http.ResponseWriter, r *http.Request) bool {
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

// GET /platform/backups
func (h *BackupHandler) PlatformGet(w http.ResponseWriter, r *http.Request) {
	if !h.platformAdmin(w, r) {
		return
	}
	v, err := h.svc.PlatformView(r.Context())
	if err != nil {
		backupError(w, err)
		return
	}
	respondJSON(w, http.StatusOK, v)
}

func (h *BackupHandler) platformStart(w http.ResponseWriter, r *http.Request, action string, start func(context.Context, *uuid.UUID) (uuid.UUID, error)) {
	if !h.platformAdmin(w, r) {
		return
	}
	if !h.svc.Enabled() {
		backupsDisabled(w)
		return
	}
	id, err := start(r.Context(), userPtr(r))
	if err != nil {
		backupError(w, err)
		return
	}
	h.svc.Audit(context.WithoutCancel(r.Context()), backup.AuditEntry{UserID: userPtr(r), Action: action, ResourceType: "backup",
		IP: middleware.ClientIP(r), NewValues: map[string]any{"run_id": id.String(), "scope": "platform"}})
	respondJSON(w, http.StatusAccepted, map[string]string{"run_id": id.String()})
}

// POST /platform/backups/run and /platform/backups/verify
func (h *BackupHandler) PlatformRun(w http.ResponseWriter, r *http.Request) {
	h.platformStart(w, r, "backup.run", h.svc.StartPlatformBackup)
}

func (h *BackupHandler) PlatformVerify(w http.ResponseWriter, r *http.Request) {
	h.platformStart(w, r, "backup.verify", h.svc.StartPlatformVerify)
}
