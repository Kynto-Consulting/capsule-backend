package handlers

import (
	"net/http"
	"strconv"

	"github.com/kynto/capsule/backend/internal/access"
)

// GET /orgs/{orgID}/assignments  (assignment:read)
func (h *accessAPI) assignmentsList(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	p, err := h.svc.ListAssignments(r.Context(), a, org, access.AssignmentQuery{
		SubjectType: q.Get("subject_type"), SubjectID: q.Get("subject_id"), ScopeType: q.Get("scope_type"), ScopeID: q.Get("scope_id"),
		TemplateID: q.Get("template_id"), ExpiringWithin: q.Get("expiring_within"), Cursor: q.Get("cursor"), Limit: queryInt(r, "limit"),
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	respondJSON(w, http.StatusOK, p)
}

// POST /orgs/{orgID}/assignments  (assignment:grant at the scope of the assignment; no-escalation)
func (h *accessAPI) assignmentsCreate(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	var in access.AssignmentInput
	raw, ok := readAccessBody(w, r, &in)
	if !ok {
		return
	}
	rep, err := h.svc.CreateAssignment(r.Context(), a, org, in, idemOf(r, raw))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeReply(w, rep)
}

// GET /orgs/{orgID}/assignments/{assignmentID}
func (h *accessAPI) assignmentsGet(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "assignmentID", "assignment")
	if !ok {
		return
	}
	v, err := h.svc.GetAssignment(r.Context(), a, org, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	respondJSON(w, http.StatusOK, v)
}

// PATCH /orgs/{orgID}/assignments/{assignmentID}
func (h *accessAPI) assignmentsPatch(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "assignmentID", "assignment")
	if !ok {
		return
	}
	var in access.PatchAssignmentInput
	raw, ok := readAccessBody(w, r, &in)
	if !ok {
		return
	}
	rep, err := h.svc.PatchAssignment(r.Context(), a, org, id, in, idemOf(r, raw))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeReply(w, rep)
}

// DELETE /orgs/{orgID}/assignments/{assignmentID}  (revoke)
func (h *accessAPI) assignmentsRevoke(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "assignmentID", "assignment")
	if !ok {
		return
	}
	rep, err := h.svc.RevokeAssignment(r.Context(), a, org, id, idemOf(r, nil))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeReply(w, rep)
}

// GET /orgs/{orgID}/projects/{projectID}/access  (who has access to the project)
func (h *accessAPI) projectAccess(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	project, ok := pathUUID(w, r, "projectID", "project")
	if !ok {
		return
	}
	p, err := h.svc.ProjectAccess(r.Context(), a, org, project, r.URL.Query().Get("cursor"), queryInt(r, "limit"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	respondJSON(w, http.StatusOK, p)
}

// PUT /orgs/{orgID}/projects/{projectID}/access-override[?confirm=true]
func (h *accessAPI) accessOverride(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	project, ok := pathUUID(w, r, "projectID", "project")
	if !ok {
		return
	}
	var in struct {
		Mode *string `json:"mode"`
	}
	raw, ok := readAccessBody(w, r, &in)
	if !ok {
		return
	}
	confirm, _ := strconv.ParseBool(r.URL.Query().Get("confirm"))
	rep, err := h.svc.SetAccessOverride(r.Context(), a, org, project, in.Mode, confirm, idemOf(r, raw))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeReply(w, rep)
}

// GET /orgs/{orgID}/users/{userID}/permissions  (assignment:read)
func (h *accessAPI) userPermissions(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	user, ok := pathUUID(w, r, "userID", "user")
	if !ok {
		return
	}
	res, err := h.svc.UserPermissions(r.Context(), a, org, user, r.URL.Query().Get("project"), r.URL.Query().Get("expand"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", res.ETag)
	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	w.Header().Set("X-Access-Epoch", strconv.FormatInt(res.Epoch, 10))
	_, _ = w.Write(res.Body)
}

// PUT /orgs/{orgID}/members/{userID}/template  (member:update)
func (h *accessAPI) memberTemplate(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	user, ok := pathUUID(w, r, "userID", "user")
	if !ok {
		return
	}
	var in struct {
		Template string `json:"template"`
	}
	raw, ok := readAccessBody(w, r, &in)
	if !ok {
		return
	}
	rep, err := h.svc.SetMemberTemplate(r.Context(), a, org, user, in.Template, idemOf(r, raw))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeReply(w, rep)
}
