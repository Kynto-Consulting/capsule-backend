package handlers

import (
	"net/http"
	"strings"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/security"
)

func renovateView(s *security.RenovateState) map[string]any {
	m := map[string]any{
		"enabled": s.Enabled, "onboarding": s.Onboarding, "open_prs": s.OpenPRs, "preset": s.Preset, "schedule": s.Schedule,
		"topic_synced": s.TopicSynced, "last_run_at": secTime(s.LastRunAt),
	}
	if s.LastRunStatus != "" {
		m["last_run_status"] = s.LastRunStatus
	}
	if s.DashboardIssueURL != "" {
		m["dashboard_issue_url"] = s.DashboardIssueURL
	}
	if s.SyncError != "" {
		m["sync_error"] = s.SyncError
	}
	return m
}

// GET .../security/renovate
func (h *SecurityHandler) RenovateGet(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityRead)
	if !ok {
		return
	}
	s, err := h.service().RenovateGet(r.Context(), c.t)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, renovateView(s))
}

type renovateBody struct {
	Enabled  *bool   `json:"enabled"`
	Preset   *string `json:"preset"`
	Schedule *string `json:"schedule"`
}

// PUT .../security/renovate
func (h *SecurityHandler) RenovatePut(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityAdmin)
	if !ok {
		return
	}
	var body renovateBody
	if !secDecode(w, r, 16<<10, &body) {
		return
	}
	s, err := h.service().RenovatePut(r.Context(), c.t, c.a, security.RenovateInput{Enabled: body.Enabled, Preset: body.Preset, Schedule: body.Schedule})
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, renovateView(s))
}

// POST .../security/renovate/run
func (h *SecurityHandler) RenovateRun(w http.ResponseWriter, r *http.Request) {
	c, ok := h.begin(w, r, authz.SecurityTriage)
	if !ok {
		return
	}
	j, err := h.service().RenovateRun(r.Context(), c.t, c.a, strings.TrimSpace(r.Header.Get("Idempotency-Key")))
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, jobView(j))
}
