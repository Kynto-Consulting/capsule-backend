package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/vpn"
)

const vk44 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestVPNFnAgentAndIntrospectFlow(t *testing.T) {
	ctx := context.Background()
	vs := &vpn.Service{Store: vpn.NewMemStore(), SecretKey: "unit-test-key-0123456789abcdef"}
	ms := fn.NewMemStore()
	fs := &fn.Service{Store: ms, VPN: vs, APIBase: "https://api.example"}
	org, proj := uuid.New(), uuid.New()
	tn, err := vs.Create(ctx, org, proj, "u", nil, vpn.Spec{Name: "estudio", Provider: "wireguard", Host: "1.2.3.4:51820", CIDRs: []string{"10.48.0.0/24"},
		Secret: `{"private_key":"` + vk44 + `","peer_public_key":"` + vk44 + `","address":"10.99.0.2/32"}`})
	if err != nil {
		t.Fatal(err)
	}
	f, err := fs.Deploy(ctx, org, proj, nil, fn.Spec{Name: "migrar", Image: "img", VPN: "estudio", Scopes: []string{"api:importacion"}})
	if err != nil {
		t.Fatal(err)
	}
	fs.Enqueue(ctx, f, fn.TriggerAPI, "user:ana", nil)
	nodeTok, nodeHash := fn.NewToken(fn.NodeTokPrefix)
	ms.Nodes[nodeHash] = "node-1"

	h := NewVPNFnHandler(nil, nil, vs, fs)
	r := chi.NewRouter()
	r.Post("/fn/tokens/introspect", h.Introspect)
	r.Post("/fn/agent/claim", h.AgentClaim)
	r.Post("/fn/agent/sync", h.AgentSync)
	r.Post("/fn/agent/runs/{runID}/finish", h.AgentFinish)
	r.Post("/fn/agent/tunnels/{tunnelID}/status", h.AgentTunnelStatus)
	do := func(path, tok string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", path, bytes.NewReader(b))
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	if w := do("/fn/agent/claim", "", nil); w.Code != 401 {
		t.Fatalf("claim without token: %d", w.Code)
	}
	if w := do("/fn/agent/claim", "capnode_unknown", nil); w.Code != 401 {
		t.Fatalf("claim with bad token: %d", w.Code)
	}
	if w := do("/fn/agent/claim", "cap_user_token", nil); w.Code != 401 {
		t.Fatalf("a user token must not act as a node: %d", w.Code)
	}
	w := do("/fn/agent/claim", nodeTok, nil)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("claim: %d %s", w.Code, w.Body)
	}
	var a fn.Assignment
	json.Unmarshal(w.Body.Bytes(), &a)
	if a.Tunnel == nil || a.Tunnel.Provider != "wireguard" || a.Env["CAPSULE_SCOPES"] != "api:importacion" {
		t.Fatalf("assignment: %+v", a)
	}
	if w := do("/fn/agent/claim", nodeTok, nil); w.Code != 204 {
		t.Fatalf("nothing else to claim: %d", w.Code)
	}

	var c fn.Claims
	w = do("/fn/tokens/introspect", "", map[string]string{"token": a.Token})
	json.Unmarshal(w.Body.Bytes(), &c)
	if !c.Active || !c.HasScope("api:importacion") || c.ProjectID != proj {
		t.Fatalf("introspect: %s", w.Body)
	}

	// tunnel status from the node: up is accepted, junk is refused
	if w := do("/fn/agent/tunnels/"+tn.ID.String()+"/status", nodeTok, map[string]any{"status": "up", "last_handshake_unix": 1760000000}); w.Code != 204 {
		t.Fatalf("status up: %d %s", w.Code, w.Body)
	}
	if w := do("/fn/agent/tunnels/"+tn.ID.String()+"/status", nodeTok, map[string]any{"status": "hacked"}); w.Code != 422 {
		t.Fatalf("junk status: %d", w.Code)
	}

	// kill switch: the node learns to stop the run and the tunnel; the token dies
	fs.DisableTunnel(ctx, tn, "user:ana")
	w = do("/fn/agent/sync", nodeTok, map[string]any{"running": []string{a.Run.ID.String()}, "tunnels": []string{tn.ID.String()}})
	var rep fn.SyncReply
	json.Unmarshal(w.Body.Bytes(), &rep)
	if len(rep.CancelRuns) != 1 || len(rep.StopTunnels) != 1 {
		t.Fatalf("sync: %s", w.Body)
	}
	if w := do("/fn/agent/tunnels/"+tn.ID.String()+"/status", nodeTok, map[string]any{"status": "up"}); w.Code != 409 {
		t.Fatalf("disabled tunnel must not report up: %d", w.Code)
	}
	w = do("/fn/tokens/introspect", "", map[string]string{"token": a.Token})
	if strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatal("token still active after kill switch")
	}
	if w := do("/fn/agent/runs/"+a.Run.ID.String()+"/finish", nodeTok, map[string]any{"status": "bogus"}); w.Code != 422 {
		t.Fatalf("finish bogus: %d", w.Code)
	}
}

func TestVPNFnNotConfigured(t *testing.T) {
	h := NewVPNFnHandler(nil, nil, nil, nil)
	w := httptest.NewRecorder()
	h.Introspect(w, httptest.NewRequest("POST", "/", strings.NewReader(`{}`)))
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("got %d", w.Code)
	}
}
