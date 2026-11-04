package handlers

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kynto/capsule/backend/internal/access"
)

// GET /orgs/{orgID}/access-audit  (audit:read; format=csv also audit:export): the access.* rows of audit_logs, newest first.
func (h *accessAPI) accessAudit(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	csvOut := q.Get("format") == "csv"
	if f := q.Get("format"); f != "" && f != "json" && f != "csv" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "format must be json or csv")
		return
	}
	p, err := h.svc.AccessAudit(r.Context(), a, org, access.AuditQuery{
		Action: q.Get("action"), Actor: q.Get("actor"), Subject: q.Get("subject"), Project: q.Get("project"),
		Since: q.Get("since"), Until: q.Get("until"), Cursor: q.Get("cursor"), Limit: queryInt(r, "limit"), CSV: csvOut,
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !csvOut {
		respondJSON(w, http.StatusOK, p)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="access-audit.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "created_at", "action", "actor_id", "actor_email", "resource_type", "resource_id", "project_id", "ip_address", "old_values", "new_values", "metadata"})
	for _, e := range p.Data {
		actorID, actorEmail, rid, pid, ip := "", "", "", "", ""
		if e.Actor != nil {
			actorID, actorEmail = e.Actor.ID.String(), e.Actor.Email
		}
		if e.ResourceID != nil {
			rid = e.ResourceID.String()
		}
		if e.ProjectID != nil {
			pid = e.ProjectID.String()
		}
		if e.IPAddress != nil {
			ip = *e.IPAddress
		}
		ov, _ := json.Marshal(e.OldValues)
		nv, _ := json.Marshal(e.NewValues)
		mv, _ := json.Marshal(e.Metadata)
		_ = cw.Write([]string{e.ID.String(), e.CreatedAt.UTC().Format(time.RFC3339), e.Action, actorID, csvSafe(actorEmail), e.ResourceType, rid, pid, ip, csvSafe(string(ov)), csvSafe(string(nv)), csvSafe(string(mv))})
	}
	cw.Flush()
}

// csvSafe neutralizes spreadsheet formula injection in cells that carry user-controlled text.
func csvSafe(s string) string {
	if s != "" && (s[0] == '=' || s[0] == '+' || s[0] == '-' || s[0] == '@') {
		return "'" + s
	}
	return s
}
