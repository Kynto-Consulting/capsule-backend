package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/internal/webhookout"
)

// NotificationsHandler serves the inbox and the preferences of the authenticated user
// (/user/notifications, /user/notification-settings). Every user only ever sees their own rows.
type NotificationsHandler struct {
	svc *gitevents.Notifier
	log *slog.Logger
}

func NewNotificationsHandler(svc *gitevents.Notifier, logger *slog.Logger) *NotificationsHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &NotificationsHandler{svc: svc, log: logger}
}

// Mount registers the routes on r (an authenticated router).
func (h *NotificationsHandler) Mount(r chi.Router) {
	r.Get("/user/notifications", h.list)
	r.Patch("/user/notifications", h.mark)
	r.Get("/user/notification-settings", h.getSettings)
	r.Put("/user/notification-settings", h.putSettings)
}

func (h *NotificationsHandler) user(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	u := middleware.GetUser(r.Context())
	if u == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return uuid.Nil, false
	}
	return u.ID, true
}

type notificationJSON struct {
	ID        uuid.UUID `json:"id"`
	Event     string    `json:"event"`
	Title     string    `json:"title"`
	URL       string    `json:"url"`
	Project   string    `json:"project"`
	Read      bool      `json:"read"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *NotificationsHandler) list(w http.ResponseWriter, r *http.Request) {
	uid, ok := h.user(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	unread, _ := strconv.ParseBool(q.Get("unread"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	rows, next, err := h.svc.List(r.Context(), uid, unread, q.Get("cursor"), limit)
	if err != nil {
		if err.Error() == "invalid cursor" {
			respondError(w, http.StatusBadRequest, "INVALID_CURSOR", "invalid cursor")
			return
		}
		h.log.Error("notifications: list failed", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		return
	}
	items := make([]notificationJSON, 0, len(rows))
	for _, n := range rows {
		items = append(items, notificationJSON{ID: n.ID, Event: n.Event, Title: n.Title, URL: n.URL, Project: n.Project, Read: n.Read, CreatedAt: n.CreatedAt})
	}
	var nc *string
	if next != "" {
		nc = &next
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nc})
}

func (h *NotificationsHandler) mark(w http.ResponseWriter, r *http.Request) {
	uid, ok := h.user(w, r)
	if !ok {
		return
	}
	var in struct {
		IDs []uuid.UUID `json:"ids"`
		All bool        `json:"all"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	if !in.All && len(in.IDs) == 0 {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "ids or all is required")
		return
	}
	if len(in.IDs) > 500 {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "at most 500 ids per call")
		return
	}
	if err := h.svc.Mark(r.Context(), uid, in.IDs, in.All); err != nil {
		h.log.Error("notifications: mark failed", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		return
	}
	respondNoContent(w)
}

func (h *NotificationsHandler) getSettings(w http.ResponseWriter, r *http.Request) {
	uid, ok := h.user(w, r)
	if !ok {
		return
	}
	st, err := h.svc.Settings(r.Context(), uid)
	if err != nil {
		h.log.Error("notifications: loading settings failed", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		return
	}
	respondJSON(w, http.StatusOK, st)
}

func (h *NotificationsHandler) putSettings(w http.ResponseWriter, r *http.Request) {
	uid, ok := h.user(w, r)
	if !ok {
		return
	}
	var in gitevents.Settings
	if !decodeBody(w, r, &in) {
		return
	}
	st, err := h.svc.SaveSettings(r.Context(), uid, in)
	if err != nil {
		if errors.Is(err, gitevents.ErrInvalidSettings) {
			respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
			return
		}
		h.log.Error("notifications: saving settings failed", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		return
	}
	respondJSON(w, http.StatusOK, st)
}

// A5Deps is what MountA5 needs from router.go.
type A5Deps struct {
	Authz  *authz.Service
	Orgs   domain.OrganizationRepository
	Audit  WebhookAuditor // optional (authz.MemberStore)
	Logger *slog.Logger
}

// MountA5 mounts the A5 routes (outbound webhooks and notifications) on the authenticated
// router r. The services come from the wiring (webhookout / gitevents shared instances); when
// the event bus was not wired (no database) the routes are simply absent.
func MountA5(r chi.Router, d A5Deps) {
	if svc := webhookout.Shared(); svc != nil {
		h := NewWebhooksHandler(d.Orgs, svc, d.Audit, d.Logger)
		h.SetAuthz(d.Authz)
		h.Mount(r)
	}
	if n := gitevents.SharedNotifier(); n != nil {
		NewNotificationsHandler(n, d.Logger).Mount(r)
	}
}
