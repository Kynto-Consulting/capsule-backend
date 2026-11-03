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
	"github.com/kynto/capsule/backend/internal/gitinsights"
)

type insightsHandler struct {
	authzHolder
	orgs domain.OrganizationRepository
	svc  *gitinsights.Service
	log  *slog.Logger
}

type activityJSON struct {
	ID        uuid.UUID  `json:"id"`
	Type      string     `json:"type"`
	Actor     personJSON `json:"actor"`
	Summary   string     `json:"summary"`
	Ref       string     `json:"ref"`
	CreatedAt time.Time  `json:"created_at"`
}

func (h *insightsHandler) scope(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid organization id")
		return uuid.Nil, false
	}
	projectID, ok := h.authorizeRoute(w, r, h.orgs, orgID, authz.GitRead)
	return projectID, ok
}

// activity: GET .../git/activity?cursor=&limit=
func (h *insightsHandler) activity(w http.ResponseWriter, r *http.Request) {
	projectID, ok := h.scope(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, next, err := h.svc.ActivityPage(r.Context(), projectID, r.URL.Query().Get("cursor"), limit)
	if err != nil {
		if errors.Is(err, gitinsights.ErrInvalidCursor) {
			respondError(w, http.StatusBadRequest, "INVALID_CURSOR", "invalid cursor")
			return
		}
		h.log.Error("activity: list failed", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		return
	}
	items := make([]activityJSON, 0, len(rows))
	for _, a := range rows {
		items = append(items, activityJSON{ID: a.ID, Type: a.Type, Actor: personJSON{UserID: a.ActorUserID, Login: a.Actor},
			Summary: a.Summary, Ref: a.Ref, CreatedAt: a.OccurredAt})
	}
	var nc *string
	if next != "" {
		nc = &next
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nc})
}

// insights: GET .../git/insights?since=&until= (default: the last 30 days, at most 366).
func (h *insightsHandler) insights(w http.ResponseWriter, r *http.Request) {
	projectID, ok := h.scope(w, r)
	if !ok {
		return
	}
	var since, until *time.Time
	if v := r.URL.Query().Get("since"); v != "" {
		t, ok := c2ParseWhen(v, false)
		if !ok {
			respondError(w, http.StatusBadRequest, "INVALID_PARAMETER", "since must be RFC 3339 or YYYY-MM-DD")
			return
		}
		since = &t
	}
	if v := r.URL.Query().Get("until"); v != "" {
		t, ok := c2ParseWhen(v, true)
		if !ok {
			respondError(w, http.StatusBadRequest, "INVALID_PARAMETER", "until must be RFC 3339 or YYYY-MM-DD")
			return
		}
		until = &t
	}
	from, to, err := h.svc.ResolveWindow(since, until)
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_PARAMETER", err.Error())
		return
	}
	out, err := h.svc.Insights(r.Context(), projectID, from, to)
	if err != nil {
		h.log.Error("insights: compute failed", "error", err)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		return
	}
	respondJSON(w, http.StatusOK, out)
}
