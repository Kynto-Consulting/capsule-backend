package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/internal/vpn"
)

// VPNFnHandler serves the VPN Connector and project functions (docs/vpn-connector.md).
// Permissions reuse existing atoms: network:read|manage for tunnels, worker:read|manage to define functions,
// cron:trigger to launch runs, log:read to read runs.
type VPNFnHandler struct {
	authzHolder
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
	vpn      *vpn.Service
	fn       *fn.Service
}

// NewVPNFnHandler builds the handler.
func NewVPNFnHandler(orgs domain.OrganizationRepository, projects domain.ProjectRepository, v *vpn.Service, f *fn.Service) *VPNFnHandler {
	return &VPNFnHandler{orgs: orgs, projects: projects, vpn: v, fn: f}
}

func actorOf(r *http.Request) (string, *uuid.UUID) {
	if u := middleware.GetUser(r.Context()); u != nil {
		id := u.ID
		return "user:" + u.Email, &id
	}
	return "unknown", nil
}

// ids parses and authorizes; it writes the response on failure.
func (h *VPNFnHandler) ids(w http.ResponseWriter, r *http.Request, perm string) (orgID, projectID uuid.UUID, ok bool) {
	if !h.ready(w) {
		return
	}
	orgID, err1 := uuid.Parse(chi.URLParam(r, "orgID"))
	projectID, err2 := uuid.Parse(chi.URLParam(r, "projectID"))
	if err1 != nil || err2 != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	if !h.authorize(w, r, h.orgs, orgID, projectID, authz.Action(perm)) {
		return
	}
	p, err := h.projects.GetByID(r.Context(), projectID)
	if err != nil || p.OrgID != orgID {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return
	}
	return orgID, projectID, true
}

// ready answers 501 when the feature is not wired (no database), like the other optional APIs.
func (h *VPNFnHandler) ready(w http.ResponseWriter) bool {
	if h.vpn == nil || h.fn == nil {
		respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "vpn connector is not configured")
		return false
	}
	return true
}

func (h *VPNFnHandler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, vpn.ErrInvalid), errors.Is(err, fn.ErrInvalid):
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", err.Error())
	case errors.Is(err, vpn.ErrConflict), errors.Is(err, fn.ErrConflict):
		respondError(w, http.StatusConflict, "CONFLICT", err.Error())
	case errors.Is(err, vpn.ErrNotFound), errors.Is(err, fn.ErrNotFound):
		respondError(w, http.StatusNotFound, "NOT_FOUND", "not found")
	case errors.Is(err, fn.ErrDisabled), errors.Is(err, vpn.ErrDisabled):
		respondError(w, http.StatusConflict, "DISABLED", err.Error())
	default:
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
	}
}

func (h *VPNFnHandler) tunnel(w http.ResponseWriter, r *http.Request, projectID uuid.UUID) *vpn.Tunnel {
	t, err := h.vpn.Store.GetByName(r.Context(), projectID, chi.URLParam(r, "name"))
	if err != nil {
		h.fail(w, err)
		return nil
	}
	return t
}

// ---- tunnels ----

// CreateVPN POST /vpn
func (h *VPNFnHandler) CreateVPN(w http.ResponseWriter, r *http.Request) {
	orgID, projectID, ok := h.ids(w, r, "network:manage")
	if !ok {
		return
	}
	var spec vpn.Spec
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&spec); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	actor, uid := actorOf(r)
	t, err := h.vpn.Create(r.Context(), orgID, projectID, actor, uid, spec)
	if err != nil {
		h.fail(w, err)
		return
	}
	out := map[string]any{"tunnel": t}
	if t.Provider == vpn.ProviderFortiGate && t.CertPin == "" {
		out["warning"] = "no certificate pin: set --cert-pin <sha256> so the remote certificate is verified"
	}
	respondJSON(w, http.StatusCreated, out)
}

// ListVPN GET /vpn
func (h *VPNFnHandler) ListVPN(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "network:read")
	if !ok {
		return
	}
	ts, err := h.vpn.Store.List(r.Context(), projectID)
	if err != nil {
		h.fail(w, err)
		return
	}
	if ts == nil {
		ts = []*vpn.Tunnel{}
	}
	respondJSON(w, http.StatusOK, ts)
}

// GetVPN GET /vpn/{name}
func (h *VPNFnHandler) GetVPN(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "network:read")
	if !ok {
		return
	}
	if t := h.tunnel(w, r, projectID); t != nil {
		respondJSON(w, http.StatusOK, t)
	}
}

// DeleteVPN DELETE /vpn/{name}
func (h *VPNFnHandler) DeleteVPN(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "network:manage")
	if !ok {
		return
	}
	t := h.tunnel(w, r, projectID)
	if t == nil {
		return
	}
	actor, _ := actorOf(r)
	if err := h.fn.DisableTunnel(r.Context(), t, actor); err != nil { // drop connections and cancel runs first
		h.fail(w, err)
		return
	}
	if err := h.vpn.Delete(r.Context(), t, actor); err != nil {
		h.fail(w, err)
		return
	}
	respondNoContent(w)
}

// SetVPNEnabled PUT /vpn/{name}/enabled  {"enabled": false} is the kill switch.
func (h *VPNFnHandler) SetVPNEnabled(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "network:manage")
	if !ok {
		return
	}
	t := h.tunnel(w, r, projectID)
	if t == nil {
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req) != nil || req.Enabled == nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "enabled (true|false) is required")
		return
	}
	actor, _ := actorOf(r)
	var err error
	if *req.Enabled {
		err = h.vpn.SetEnabled(r.Context(), t, true, actor)
	} else {
		err = h.fn.DisableTunnel(r.Context(), t, actor)
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	nt, _ := h.vpn.Store.GetByID(r.Context(), t.ID)
	respondJSON(w, http.StatusOK, nt)
}

// VPNEvents GET /vpn/{name}/events
func (h *VPNFnHandler) VPNEvents(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "log:read")
	if !ok {
		return
	}
	t := h.tunnel(w, r, projectID)
	if t == nil {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	ev, err := h.vpn.Store.Events(r.Context(), t.ID, limit)
	if err != nil {
		h.fail(w, err)
		return
	}
	if ev == nil {
		ev = []vpn.Event{}
	}
	respondJSON(w, http.StatusOK, ev)
}

// ---- functions ----

// DeployFn POST /fn/functions
func (h *VPNFnHandler) DeployFn(w http.ResponseWriter, r *http.Request) {
	orgID, projectID, ok := h.ids(w, r, "worker:manage")
	if !ok {
		return
	}
	var spec fn.Spec
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&spec); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	_, uid := actorOf(r)
	f, err := h.fn.Deploy(r.Context(), orgID, projectID, uid, spec)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusCreated, f)
}

// ListFn GET /fn/functions
func (h *VPNFnHandler) ListFn(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "worker:read")
	if !ok {
		return
	}
	fs, err := h.fn.Store.ListFunctions(r.Context(), projectID)
	if err != nil {
		h.fail(w, err)
		return
	}
	if fs == nil {
		fs = []*fn.Function{}
	}
	respondJSON(w, http.StatusOK, fs)
}

func (h *VPNFnHandler) function(w http.ResponseWriter, r *http.Request, projectID uuid.UUID) *fn.Function {
	f, err := h.fn.Store.GetFunction(r.Context(), projectID, chi.URLParam(r, "name"))
	if err != nil {
		h.fail(w, err)
		return nil
	}
	return f
}

// GetFn GET /fn/functions/{name}
func (h *VPNFnHandler) GetFn(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "worker:read")
	if !ok {
		return
	}
	if f := h.function(w, r, projectID); f != nil {
		respondJSON(w, http.StatusOK, f)
	}
}

// DeleteFn DELETE /fn/functions/{name}
func (h *VPNFnHandler) DeleteFn(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "worker:manage")
	if !ok {
		return
	}
	f := h.function(w, r, projectID)
	if f == nil {
		return
	}
	if err := h.fn.Store.DeleteFunction(r.Context(), f.ID); err != nil {
		h.fail(w, err)
		return
	}
	respondNoContent(w)
}

func (h *VPNFnHandler) enqueue(trigger string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, projectID, ok := h.ids(w, r, "cron:trigger")
		if !ok {
			return
		}
		f := h.function(w, r, projectID)
		if f == nil {
			return
		}
		var body struct {
			Payload json.RawMessage `json:"payload"`
		}
		_ = json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&body)
		actor, _ := actorOf(r)
		run, err := h.fn.Enqueue(r.Context(), f, trigger, actor, body.Payload)
		if err != nil {
			h.fail(w, err)
			return
		}
		respondJSON(w, http.StatusAccepted, run)
	}
}

// RunFn POST /fn/functions/{name}/run (API trigger) and EnqueueFn (queue trigger).
func (h *VPNFnHandler) RunFn(w http.ResponseWriter, r *http.Request) { h.enqueue(fn.TriggerAPI)(w, r) }
func (h *VPNFnHandler) EnqueueFn(w http.ResponseWriter, r *http.Request) {
	h.enqueue(fn.TriggerQueue)(w, r)
}

// ListRuns GET /fn/functions/{name}/runs
func (h *VPNFnHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "log:read")
	if !ok {
		return
	}
	f := h.function(w, r, projectID)
	if f == nil {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	runs, err := h.fn.Store.ListRuns(r.Context(), f.ID, limit)
	if err != nil {
		h.fail(w, err)
		return
	}
	if runs == nil {
		runs = []*fn.Run{}
	}
	respondJSON(w, http.StatusOK, runs)
}

// GetRun GET /fn/runs/{runID}
func (h *VPNFnHandler) GetRun(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "log:read")
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid run id")
		return
	}
	run, err := h.fn.Store.GetRun(r.Context(), id)
	if err != nil || run.ProjectID != projectID {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "run not found")
		return
	}
	respondJSON(w, http.StatusOK, run)
}

// CancelRun POST /fn/runs/{runID}/cancel
func (h *VPNFnHandler) CancelRun(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := h.ids(w, r, "cron:trigger")
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid run id")
		return
	}
	run, err := h.fn.Store.GetRun(r.Context(), id)
	if err != nil || run.ProjectID != projectID {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "run not found")
		return
	}
	if err := h.fn.Cancel(r.Context(), run); err != nil {
		h.fail(w, err)
		return
	}
	run, _ = h.fn.Store.GetRun(r.Context(), id)
	respondJSON(w, http.StatusOK, run)
}

// ---- introspection (customer apps) ----

// Introspect POST /api/v1/fn/tokens/introspect {"token": "capfn_..."}. Public: the token is the credential; the reply for an
// unknown or dead token is just {"active": false}.
func (h *VPNFnHandler) Introspect(w http.ResponseWriter, r *http.Request) {
	if !h.ready(w) {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req) != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	respondJSON(w, http.StatusOK, h.fn.Introspect(r.Context(), req.Token))
}

// ---- work node (outbound only; capnode_ token) ----

func (h *VPNFnHandler) node(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !h.ready(w) {
		return "", false
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !strings.HasPrefix(tok, fn.NodeTokPrefix) {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "node token required")
		return "", false
	}
	hash := fn.HashToken(tok)
	name, err := h.fn.Store.NodeByHash(r.Context(), hash)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "unknown node")
		return "", false
	}
	return name, true
}

// AgentClaim POST /internal/fn/agent/claim
func (h *VPNFnHandler) AgentClaim(w http.ResponseWriter, r *http.Request) {
	node, ok := h.node(w, r)
	if !ok {
		return
	}
	a, err := h.fn.Claim(r.Context(), node)
	if err != nil {
		h.fail(w, err)
		return
	}
	if a == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusOK, a)
}

// AgentSync POST /internal/fn/agent/sync  {"running":[run ids],"tunnels":[tunnel ids]}
func (h *VPNFnHandler) AgentSync(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.node(w, r); !ok {
		return
	}
	var req struct {
		Running []uuid.UUID `json:"running"`
		Tunnels []uuid.UUID `json:"tunnels"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req) != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	rep, err := h.fn.Sync(r.Context(), req.Running, req.Tunnels)
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusOK, rep)
}

// AgentFinish POST /internal/fn/agent/runs/{runID}/finish
func (h *VPNFnHandler) AgentFinish(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.node(w, r); !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "runID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid run id")
		return
	}
	var req struct {
		Status   string `json:"status"`
		ExitCode *int   `json:"exit_code"`
		BytesIn  int64  `json:"bytes_in"`
		BytesOut int64  `json:"bytes_out"`
		LogTail  string `json:"log_tail"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&req) != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	switch req.Status {
	case fn.RunSucceeded, fn.RunFailed, fn.RunTimeout, fn.RunCancelled:
	default:
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "bad status")
		return
	}
	if len(req.LogTail) > 16<<10 {
		req.LogTail = req.LogTail[len(req.LogTail)-16<<10:]
	}
	if err := h.fn.Finish(r.Context(), id, req.Status, req.ExitCode, req.BytesIn, req.BytesOut, req.LogTail); err != nil {
		h.fail(w, err)
		return
	}
	respondNoContent(w)
}

// AgentTunnelStatus POST /internal/fn/agent/tunnels/{tunnelID}/status
func (h *VPNFnHandler) AgentTunnelStatus(w http.ResponseWriter, r *http.Request) {
	node, ok := h.node(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "tunnelID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid tunnel id")
		return
	}
	var req struct {
		Status    string `json:"status"`
		Handshake *int64 `json:"last_handshake_unix"`
		Error     string `json:"error"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req) != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	t, err := h.vpn.Store.GetByID(r.Context(), id)
	if err != nil {
		h.fail(w, err)
		return
	}
	switch req.Status {
	case vpn.StatusUp, vpn.StatusDown, vpn.StatusConnecting, vpn.StatusError:
	default:
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "bad status")
		return
	}
	var hs *time.Time
	if req.Handshake != nil && *req.Handshake > 0 {
		x := time.Unix(*req.Handshake, 0)
		hs = &x
	}
	if err := h.vpn.Report(r.Context(), t, req.Status, hs, req.Error, "node:"+node); err != nil {
		h.fail(w, err)
		return
	}
	respondNoContent(w)
}
