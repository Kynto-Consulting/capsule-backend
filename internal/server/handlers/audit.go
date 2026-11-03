package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitaudit"
	"github.com/kynto/capsule/backend/internal/gitinsights"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// C2Deps is what MountC2 needs from router.go.
type C2Deps struct {
	Authz  *authz.Service
	Orgs   domain.OrganizationRepository
	Logger *slog.Logger
}

type c2Services struct {
	audit    *gitaudit.Service
	recorder *gitaudit.Recorder
	insights *gitinsights.Service
}

var (
	c2Mu  sync.RWMutex
	c2Svc c2Services
)

// WireC2 publishes the services of Git Capsule package C2 for the handlers (called by the wiring).
// Any of them may be nil: the routes that need it are then simply absent.
func WireC2(audit *gitaudit.Service, recorder *gitaudit.Recorder, insights *gitinsights.Service) {
	c2Mu.Lock()
	c2Svc = c2Services{audit: audit, recorder: recorder, insights: insights}
	c2Mu.Unlock()
}

// MountC2 mounts, on the authenticated router r:
//
//	GET /orgs/{orgID}/audit-log                         auditLog (JSON, or CSV with ?format=csv)   org.admin
//	GET /orgs/{orgID}/projects/{projectID}/git/activity activityList                                git.read
//	GET /orgs/{orgID}/projects/{projectID}/git/insights insights                                    git.read
//
// Only GET is ever registered: there is no way to edit or delete an audit row through HTTP. The
// activity and insights routes read git_activity; mounted after package B1 they take over its
// Forgejo-derived versions of the same paths.
func MountC2(r chi.Router, d C2Deps) {
	c2Mu.RLock()
	s := c2Svc
	c2Mu.RUnlock()
	log := d.Logger
	if log == nil {
		log = slog.Default()
	}
	if s.audit != nil {
		h := &auditHandler{orgs: d.Orgs, svc: s.audit, rec: s.recorder, log: log}
		r.Get("/orgs/{orgID}/audit-log", h.list)
	}
	if s.insights != nil {
		h := &insightsHandler{orgs: d.Orgs, svc: s.insights, log: log}
		h.SetAuthz(d.Authz)
		r.Get("/orgs/{orgID}/projects/{projectID}/git/activity", h.activity)
		r.Get("/orgs/{orgID}/projects/{projectID}/git/insights", h.insights)
	}
}

type auditHandler struct {
	orgs domain.OrganizationRepository
	svc  *gitaudit.Service
	rec  *gitaudit.Recorder
	log  *slog.Logger
}

type personJSON struct {
	UserID *uuid.UUID `json:"user_id"`
	Login  string     `json:"login"`
	Name   string     `json:"name"`
	Email  string     `json:"email"`
}

type auditEntryJSON struct {
	ID           uuid.UUID      `json:"id"`
	Action       string         `json:"action"`
	Actor        personJSON     `json:"actor"`
	ProjectID    *uuid.UUID     `json:"project_id"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	IP           string         `json:"ip"`
	UserAgent    string         `json:"user_agent"`
	OldValues    map[string]any `json:"old_values"`
	NewValues    map[string]any `json:"new_values"`
	Metadata     map[string]any `json:"metadata"`
	CreatedAt    time.Time      `json:"created_at"`
}

func toAuditJSON(e gitaudit.Entry) auditEntryJSON {
	rid := ""
	if e.ResourceID != nil {
		rid = e.ResourceID.String()
	}
	login := e.ActorLabel
	if login == "" {
		login = e.ActorEmail
	}
	return auditEntryJSON{ID: e.ID, Action: e.Action, Actor: personJSON{UserID: e.UserID, Login: login, Name: e.ActorName, Email: e.ActorEmail},
		ProjectID: e.ProjectID, ResourceType: e.ResourceType, ResourceID: rid, IP: e.IP, UserAgent: e.UserAgent,
		OldValues: e.OldValues, NewValues: e.NewValues, Metadata: e.Metadata, CreatedAt: e.CreatedAt}
}

func c2ParseWhen(s string, endOfDay bool) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), true
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		t = t.UTC()
		if endOfDay {
			t = t.Add(24*time.Hour - time.Microsecond)
		}
		return t, true
	}
	return time.Time{}, false
}

// requireOrgAdmin enforces org.admin: an owner or admin of the organization.
func requireOrgAdmin(w http.ResponseWriter, r *http.Request, orgs domain.OrganizationRepository, orgID uuid.UUID) (*domain.User, bool) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return nil, false
	}
	role, err := orgs.GetMemberRole(r.Context(), orgID, user.ID)
	if err != nil {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member of this organization")
		return nil, false
	}
	if role != "owner" && role != "admin" {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "only owners and admins can read the audit log")
		return nil, false
	}
	return user, true
}

func (h *auditHandler) filter(w http.ResponseWriter, r *http.Request, orgID uuid.UUID) (gitaudit.Filter, bool) {
	q := r.URL.Query()
	f := gitaudit.Filter{Action: strings.TrimSpace(q.Get("action")), Actor: strings.TrimSpace(q.Get("actor"))}
	if v := q.Get("since"); v != "" {
		t, ok := c2ParseWhen(v, false)
		if !ok {
			respondError(w, http.StatusBadRequest, "INVALID_PARAMETER", "since must be RFC 3339 or YYYY-MM-DD")
			return f, false
		}
		f.Since = &t
	}
	if v := q.Get("until"); v != "" {
		t, ok := c2ParseWhen(v, true)
		if !ok {
			respondError(w, http.StatusBadRequest, "INVALID_PARAMETER", "until must be RFC 3339 or YYYY-MM-DD")
			return f, false
		}
		f.Until = &t
	}
	if v := strings.TrimSpace(q.Get("project")); v != "" {
		id, ok, err := h.svc.ResolveProject(r.Context(), orgID, v)
		if err != nil {
			h.log.Error("audit: resolving project failed", "error", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
			return f, false
		}
		if !ok {
			respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
			return f, false
		}
		f.ProjectID = &id
	}
	if err := f.Validate(); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_PARAMETER", err.Error())
		return f, false
	}
	return f, true
}

func (h *auditHandler) list(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid organization id")
		return
	}
	user, ok := requireOrgAdmin(w, r, h.orgs, orgID)
	if !ok {
		return
	}
	f, ok := h.filter(w, r, orgID)
	if !ok {
		return
	}
	q := r.URL.Query()
	if q.Get("format") == "csv" || strings.Contains(r.Header.Get("Accept"), "text/csv") {
		h.exportCSV(w, r, orgID, user.ID, f)
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	rows, next, err := h.svc.List(r.Context(), orgID, f, q.Get("cursor"), limit)
	if err != nil {
		if errors.Is(err, gitaudit.ErrInvalidCursor) {
			respondError(w, http.StatusBadRequest, "INVALID_CURSOR", "invalid cursor")
			return
		}
		h.log.Error("audit: list failed", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		return
	}
	items := make([]auditEntryJSON, 0, len(rows))
	for _, e := range rows {
		items = append(items, toAuditJSON(e))
	}
	var nc *string
	if next != "" {
		nc = &next
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nc})
}

// exportCSV streams the CSV. The export itself is audited first and fails closed: no audit row,
// no export.
func (h *auditHandler) exportCSV(w http.ResponseWriter, r *http.Request, orgID, userID uuid.UUID, f gitaudit.Filter) {
	if _, err := gitaudit.ParseCursor(r.URL.Query().Get("cursor")); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_CURSOR", "invalid cursor")
		return
	}
	if h.rec != nil {
		filt := map[string]any{"action": f.Action, "actor": f.Actor}
		if f.ProjectID != nil {
			filt["project_id"] = f.ProjectID.String()
		}
		if f.Since != nil {
			filt["since"] = f.Since.Format(time.RFC3339)
		}
		if f.Until != nil {
			filt["until"] = f.Until.Format(time.RFC3339)
		}
		if err := h.rec.Record(r.Context(), gitaudit.Input{OrgID: orgID, UserID: userID, Action: gitaudit.ActAuditExport,
			ResourceType: gitaudit.ResAuditLog, ResourceID: orgID, IP: middleware.ClientIP(r), UserAgent: r.UserAgent(),
			New: map[string]any{"format": "csv", "filter": filt}}); err != nil {
			h.log.Error("audit: recording the export failed", "error", err)
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
			return
		}
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/csv; charset=utf-8")
	hd.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"audit-log-%s.csv\"", time.Now().UTC().Format("20060102-150405")))
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Trailer", "X-Capsule-Export-Truncated, X-Capsule-Next-Cursor")
	w.WriteHeader(http.StatusOK)
	res, err := h.svc.Export(r.Context(), orgID, f, r.URL.Query().Get("cursor"), 0, w)
	if err != nil {
		h.log.Error("audit: export aborted", "error", err)
		return // headers are out; the truncated CSV is the signal
	}
	hd.Set("X-Capsule-Export-Truncated", strconv.FormatBool(res.Truncated))
	hd.Set("X-Capsule-Next-Cursor", res.Next)
}
