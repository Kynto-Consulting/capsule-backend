package handlers

import (
	"net/http"

	"github.com/kynto/capsule/backend/internal/access"
)

// POST /orgs/{orgID}/access/simulate  (assignment:read): can X do Y on Z, and why (Engine.Explain), with optional what_if.
func (h *accessAPI) simulate(w http.ResponseWriter, r *http.Request) {
	a, org, ok := h.begin(w, r)
	if !ok {
		return
	}
	var in access.SimulateInput
	if _, ok := readAccessBody(w, r, &in); !ok {
		return
	}
	d, err := h.svc.Simulate(r.Context(), a, org, in)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	respondJSON(w, http.StatusOK, d)
}
