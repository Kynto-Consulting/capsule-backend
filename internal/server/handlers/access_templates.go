package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/kynto/capsule/backend/internal/access"
)

// GET /orgs/{orgID}/templates  (template:read)
func (h *accessAPI) templatesList(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	inc, _ := strconv.ParseBool(r.URL.Query().Get("include_archived"))
	list, err := h.svc.ListTemplates(r.Context(), a, org, r.URL.Query().Get("kind"), inc)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": list})
}

// POST /orgs/{orgID}/templates  (template:manage; create, or clone with cloned_from)
func (h *accessAPI) templatesCreate(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	var in access.TemplateInput
	raw, ok := readAccessBody(w, r, &in)
	if !ok {
		return
	}
	rep, err := h.svc.CreateTemplate(r.Context(), a, org, in, idemOf(r, raw))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeReply(w, rep)
}

// GET /orgs/{orgID}/templates/{templateID}
func (h *accessAPI) templatesGet(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "templateID", "template")
	if !ok {
		return
	}
	t, err := h.svc.GetTemplate(r.Context(), a, org, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	respondJSON(w, http.StatusOK, t)
}

// PUT /orgs/{orgID}/templates/{templateID}[?dry_run=true]  (publish version n+1, or preview the impact)
func (h *accessAPI) templatesPublish(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "templateID", "template")
	if !ok {
		return
	}
	var in access.TemplateInput
	raw, ok := readAccessBody(w, r, &in)
	if !ok {
		return
	}
	dry, _ := strconv.ParseBool(r.URL.Query().Get("dry_run"))
	var idem *access.Idem
	if !dry {
		idem = idemOf(r, raw)
	}
	rep, err := h.svc.PublishTemplate(r.Context(), a, org, id, in, dry, idem)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeReply(w, rep)
}

// DELETE /orgs/{orgID}/templates/{templateID}  (archive when in use, delete otherwise)
func (h *accessAPI) templatesDelete(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "templateID", "template")
	if !ok {
		return
	}
	rep, err := h.svc.DeleteTemplate(r.Context(), a, org, id, idemOf(r, nil))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeReply(w, rep)
}

// GET /orgs/{orgID}/templates/{templateID}/versions
func (h *accessAPI) templatesVersions(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "templateID", "template")
	if !ok {
		return
	}
	v, err := h.svc.ListTemplateVersions(r.Context(), a, org, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": v})
}

// GET /orgs/{orgID}/templates/{templateID}/versions/{from}/diff/{to}
func (h *accessAPI) templatesDiff(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	id, ok := pathUUID(w, r, "templateID", "template")
	if !ok {
		return
	}
	from, err1 := strconv.Atoi(chi.URLParam(r, "from"))
	to, err2 := strconv.Atoi(chi.URLParam(r, "to"))
	if err1 != nil || err2 != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid version number")
		return
	}
	d, err := h.svc.DiffTemplateVersions(r.Context(), a, org, id, from, to)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	respondJSON(w, http.StatusOK, d)
}
