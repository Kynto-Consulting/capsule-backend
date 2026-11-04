package handlers

import (
	"net/http"
	"strconv"

	"github.com/kynto/capsule/backend/internal/access"
)

func queryInt(r *http.Request, name string) int {
	n, _ := strconv.Atoi(r.URL.Query().Get(name))
	return n
}

// GET /orgs/{orgID}/groups  (group:read)
func (h *accessAPI) groupsList(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	inc, _ := strconv.ParseBool(r.URL.Query().Get("include_archived"))
	p, err := h.svc.ListGroups(r.Context(), a, org, r.URL.Query().Get("q"), r.URL.Query().Get("cursor"), queryInt(r, "limit"), inc)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	respondJSON(w, http.StatusOK, p)
}

// POST /orgs/{orgID}/groups  (group:manage)
func (h *accessAPI) groupsCreate(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	var in access.GroupInput
	raw, ok := readAccessBody(w, r, &in)
	if !ok {
		return
	}
	rep, err := h.svc.CreateGroup(r.Context(), a, org, in, idemOf(r, raw))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeReply(w, rep)
}

// GET /orgs/{orgID}/groups/{groupID}
func (h *accessAPI) groupsGet(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "groupID", "group")
	if !ok {
		return
	}
	g, err := h.svc.GetGroup(r.Context(), a, org, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	respondJSON(w, http.StatusOK, g)
}

// PATCH /orgs/{orgID}/groups/{groupID}
func (h *accessAPI) groupsUpdate(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "groupID", "group")
	if !ok {
		return
	}
	var in access.GroupInput
	raw, ok := readAccessBody(w, r, &in)
	if !ok {
		return
	}
	rep, err := h.svc.UpdateGroup(r.Context(), a, org, id, in, idemOf(r, raw))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeReply(w, rep)
}

// DELETE /orgs/{orgID}/groups/{groupID}  (archive)
func (h *accessAPI) groupsArchive(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "groupID", "group")
	if !ok {
		return
	}
	rep, err := h.svc.ArchiveGroup(r.Context(), a, org, id, idemOf(r, nil))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeReply(w, rep)
}

// GET /orgs/{orgID}/groups/{groupID}/members
func (h *accessAPI) groupMembersList(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "groupID", "group")
	if !ok {
		return
	}
	p, err := h.svc.ListGroupMembers(r.Context(), a, org, id, r.URL.Query().Get("cursor"), queryInt(r, "limit"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	respondJSON(w, http.StatusOK, p)
}

// POST /orgs/{orgID}/groups/{groupID}/members  (group:manage + containment of what the group grants)
func (h *accessAPI) groupMembersAdd(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "groupID", "group")
	if !ok {
		return
	}
	var in access.AddMembersInput
	raw, ok := readAccessBody(w, r, &in)
	if !ok {
		return
	}
	rep, err := h.svc.AddGroupMembers(r.Context(), a, org, id, in, idemOf(r, raw))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeReply(w, rep)
}

// DELETE /orgs/{orgID}/groups/{groupID}/members/{userID}
func (h *accessAPI) groupMembersRemove(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "groupID", "group")
	if !ok {
		return
	}
	user, ok := pathUUID(w, r, "userID", "user")
	if !ok {
		return
	}
	rep, err := h.svc.RemoveGroupMember(r.Context(), a, org, id, user, idemOf(r, nil))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeReply(w, rep)
}
