package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/environments"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

func (h *EnvironmentsHandler) promotionID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "promotionID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid promotion id")
		return uuid.Nil, false
	}
	return id, true
}

// POST .../promotions (Idempotency-Key honored)
func (h *EnvironmentsHandler) PromotionCreate(w http.ResponseWriter, r *http.Request) {
	t, a, ok := h.target(w, r, authz.EnvRequest)
	if !ok {
		return
	}
	var req environments.PromotionRequest
	if !envDecode(w, r, &req) {
		return
	}
	v, created, err := h.svc.CreatePromotion(r.Context(), t, a, req, strings.TrimSpace(r.Header.Get("Idempotency-Key")))
	if err != nil {
		h.fail(w, err)
		return
	}
	if !created {
		w.Header().Set("Idempotent-Replay", "true")
	}
	respondJSON(w, http.StatusAccepted, v)
}

// GET .../promotions/{promotionID}
func (h *EnvironmentsHandler) PromotionGet(w http.ResponseWriter, r *http.Request) {
	t, a, ok := h.target(w, r, authz.EnvRead)
	if !ok {
		return
	}
	id, ok := h.promotionID(w, r)
	if !ok {
		return
	}
	v, err := h.svc.GetPromotion(r.Context(), t, a, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, v)
}

type decisionBody struct {
	Comment *string `json:"comment"`
}

func (h *EnvironmentsHandler) decide(w http.ResponseWriter, r *http.Request, approve bool) {
	// env.approve is granted by the environment's approver list, not by role: any visible member
	// passes the gate here and the service enforces the list (and, in production, the admin role).
	t, a, ok := h.target(w, r, authz.EnvRead)
	if !ok {
		return
	}
	id, ok := h.promotionID(w, r)
	if !ok {
		return
	}
	var b decisionBody
	if !envDecode(w, r, &b) {
		return
	}
	if b.Comment == nil {
		envError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "comment is required",
			[]environments.FieldError{{Field: "comment", Message: "required"}})
		return
	}
	var (
		v   environments.PromotionView
		err error
	)
	if approve {
		v, err = h.svc.Approve(r.Context(), t, a, id, *b.Comment)
	} else {
		v, err = h.svc.Reject(r.Context(), t, a, id, *b.Comment)
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, v)
}

// POST .../promotions/{promotionID}/approve
func (h *EnvironmentsHandler) PromotionApprove(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, true)
}

// POST .../promotions/{promotionID}/reject
func (h *EnvironmentsHandler) PromotionReject(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, false)
}

// POST .../promotions/{promotionID}/cancel
func (h *EnvironmentsHandler) PromotionCancel(w http.ResponseWriter, r *http.Request) {
	t, a, ok := h.target(w, r, authz.EnvRead)
	if !ok {
		return
	}
	id, ok := h.promotionID(w, r)
	if !ok {
		return
	}
	v, err := h.svc.Cancel(r.Context(), t, a, id)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, v)
}

// GET /orgs/{orgID}/approvals
func (h *EnvironmentsHandler) ApprovalsPending(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "environments are not configured")
		return
	}
	u := middleware.GetUser(r.Context())
	if u == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return
	}
	if ok, _ := h.orgs.IsMember(r.Context(), orgID, u.ID); !ok {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, next, err := h.svc.Pending(r.Context(), orgID, u.ID, r.URL.Query().Get("cursor"), limit)
	if err != nil {
		if strings.Contains(err.Error(), "invalid cursor") {
			envError(w, http.StatusBadRequest, "INVALID_CURSOR", "invalid cursor", nil)
			return
		}
		h.fail(w, err)
		return
	}
	if items == nil {
		items = []environments.PromotionView{}
	}
	var nc any
	if next != "" {
		nc = next
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nc})
}
