package handlers

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/go-chi/chi/v5"

	"github.com/kynto/capsule/backend/internal/vpn"
	"github.com/kynto/capsule/backend/internal/vpn/gateway"
)

// SetRelay wires the relay that lets Lambda functions reach a tunnel without NAT (docs/vpn-connector.md, section 7).
func (h *VPNFnHandler) SetRelay(r *gateway.Relay) { h.relay = r }

// bufConn keeps the bytes the HTTP server had already buffered when the connection was hijacked.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// upgrade takes over the connection after answering 101. The server's own deadlines are cleared: these connections are long lived.
func upgrade(w http.ResponseWriter, proto string) (net.Conn, error) {
	conn, rw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n", proto); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if rw != nil && rw.Reader.Buffered() > 0 {
		return bufConn{conn, rw.Reader}, nil
	}
	return conn, nil
}

func (h *VPNFnHandler) relayReady(w http.ResponseWriter) bool {
	if !h.ready(w) {
		return false
	}
	if h.relay == nil {
		respondError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "relay is not configured")
		return false
	}
	return true
}

// RelayNode POST /api/v1/fn/relay/node/{tunnelID}: a work node offers one idle connection (outbound, node token). The node can
// only serve tunnels of Lambda runs that were assigned to it.
func (h *VPNFnHandler) RelayNode(w http.ResponseWriter, r *http.Request) {
	if !h.relayReady(w) {
		return
	}
	node, ok := h.node(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "tunnelID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid tunnel id")
		return
	}
	if !h.fn.NodeServesTunnel(r.Context(), node, id) {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "this node serves no running lambda run on that tunnel")
		return
	}
	conn, err := upgrade(w, "capsule-relay")
	if err != nil {
		return
	}
	h.relay.Offer(id.String(), conn)
}

// RelayConnect POST /api/v1/fn/relay/connect with `Authorization: Bearer capfn_...` and `X-Capsule-Dest: ip:port`: a Lambda
// asks for a connection inside its function's tunnel. Destinations outside the declared networks are refused and audited.
func (h *VPNFnHandler) RelayConnect(w http.ResponseWriter, r *http.Request) {
	if !h.relayReady(w) {
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims, t, ok := h.fn.RelayTarget(r.Context(), tok)
	if !ok {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "run token is not valid for a tunnel")
		return
	}
	cidrs, err := gateway.ParsePolicyCIDRs(t.CIDRs)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "tunnel networks are invalid")
		return
	}
	policy := gateway.Policy{AllowedCIDRs: cidrs, OnDenied: func(target, reason string) {
		h.vpn.Audit(r.Context(), t, vpn.EventDeniedTarget, fmt.Sprintf("function %s run %s tried %s: %s", claims.Function, claims.RunID, target, reason), "run:"+claims.RunID.String())
	}}
	node, err := h.relay.Open(r.Context(), t.ID.String(), r.Header.Get("X-Capsule-Dest"), policy)
	if err != nil {
		switch {
		case errors.Is(err, gateway.ErrRelayBadRequest):
			respondError(w, http.StatusBadRequest, "INVALID_DESTINATION", "destination must be ip:port")
		case errors.Is(err, gateway.ErrRelayDenied):
			respondError(w, http.StatusForbidden, "DESTINATION_DENIED", "destination is outside the networks declared for the tunnel")
		case errors.Is(err, gateway.ErrRelayCeiling):
			respondError(w, http.StatusTooManyRequests, "CEILING", "the tunnel's connection ceiling is reached")
		case errors.Is(err, gateway.ErrRelayNoNode):
			respondError(w, http.StatusServiceUnavailable, "NODE_UNAVAILABLE", "the tunnel's node is not attached")
		default:
			respondError(w, http.StatusBadGateway, "UNREACHABLE", "the destination could not be reached through the tunnel")
		}
		return
	}
	conn, err := upgrade(w, "capsule-relay")
	if err != nil {
		_ = node.Close()
		return
	}
	h.relay.Splice(claims.RunID.String(), conn, node)
}
