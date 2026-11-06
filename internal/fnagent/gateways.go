package fnagent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/vpn"
	"github.com/kynto/capsule/backend/internal/vpn/gateway"
)

// Tunnel is an open tunnel owned by the gateway. Only Dial is exposed to the SOCKS side.
type Tunnel interface {
	gateway.Dialer
	// Health reports up|connecting|error, the last handshake and a message.
	Health() (status string, handshake time.Time, msg string)
	Close()
}

// KernelFactory opens the namespace based providers (fortigate, ipsec, openvpn). Set by kernel_linux.go.
var KernelFactory func(ta fn.TunnelAssignment) (Tunnel, error)

type wgTunnel struct {
	*gateway.WireGuardTunnel
}

func (w wgTunnel) Health() (string, time.Time, string) {
	hs := w.LastHandshake()
	switch {
	case hs.IsZero():
		return vpn.StatusConnecting, hs, "waiting for the first handshake"
	case time.Since(hs) > 3*time.Minute:
		return vpn.StatusError, hs, "no handshake for more than 3 minutes"
	}
	return vpn.StatusUp, hs, ""
}

// OpenTunnel opens the right provider. WireGuard runs in userspace (no interface, routes or DNS on the host).
func OpenTunnel(ta fn.TunnelAssignment, red *vpn.Redactor) (Tunnel, error) {
	if ta.Provider == vpn.ProviderWireGuard {
		var sec vpn.WGSecret
		if err := json.Unmarshal([]byte(ta.Secret), &sec); err != nil {
			return nil, err
		}
		t, err := gateway.StartWireGuard(gateway.WGParams{Secret: sec, Endpoint: ta.Host, AllowedIPs: ta.CIDRs, Logf: func(s string) { fmt.Fprintln(os.Stderr, "wg:", red.Mask(s)) }})
		if err != nil {
			return nil, err
		}
		return wgTunnel{t}, nil
	}
	if KernelFactory == nil {
		return nil, fmt.Errorf("provider %s needs Linux network namespaces on this node", ta.Provider)
	}
	return KernelFactory(ta)
}

type gw struct {
	id      uuid.UUID
	version int64
	t       Tunnel
	limits  *gateway.Limits
	policy  gateway.Policy
	lastSt  string
}

// Manager keeps one gateway per tunnel (a changed version restarts it) and one SOCKS endpoint per run.
type Manager struct {
	Open  func(ta fn.TunnelAssignment, red *vpn.Redactor) (Tunnel, error)
	Audit func(tunnel uuid.UUID, target, reason string)

	mu  sync.Mutex
	gws map[uuid.UUID]*gw
}

// NewManager creates a Manager that opens real tunnels.
func NewManager() *Manager { return &Manager{Open: OpenTunnel, gws: map[uuid.UUID]*gw{}} }

// Ensure returns the gateway of the tunnel, (re)starting it when needed.
func (m *Manager) Ensure(ta fn.TunnelAssignment) (*gw, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g, ok := m.gws[ta.ID]; ok {
		st, _, _ := g.t.Health()
		if g.version == ta.Version && st != vpn.StatusError {
			return g, nil
		}
		// credentials or networks changed, or the tunnel died: a FortiGate ends an SSL-VPN session after its idle timeout (5 min
		// without traffic) and openfortivpn exits. Before, the dead gateway was handed out forever and no run could reach the
		// remote network until the agent restarted (06-nov-2026). Health reports error only after its own grace (90 s for kernel
		// tunnels), so a gateway that is still coming up is not restarted in a loop.
		g.t.Close()
		delete(m.gws, ta.ID)
	}
	red := vpn.NewRedactor()
	red.AddJSONValues(ta.Secret)
	t, err := m.Open(ta, red)
	if err != nil {
		return nil, fmt.Errorf("%s", red.Mask(err.Error()))
	}
	cidrs, err := gateway.ParsePolicyCIDRs(ta.CIDRs)
	if err != nil {
		t.Close()
		return nil, err
	}
	g := &gw{id: ta.ID, version: ta.Version, t: t, limits: gateway.NewLimits(ta.MaxConns, ta.BandwidthBps)}
	g.policy = gateway.Policy{AllowedCIDRs: cidrs, OnDenied: func(target, reason string) {
		if m.Audit != nil {
			m.Audit(ta.ID, target, reason)
		}
	}}
	m.gws[ta.ID] = g
	return g, nil
}

// Stop closes one tunnel (kill switch / deleted).
func (m *Manager) Stop(id uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g, ok := m.gws[id]; ok {
		g.t.Close()
		delete(m.gws, id)
	}
}

// IDs lists the tunnels kept up.
func (m *Manager) IDs() []uuid.UUID {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]uuid.UUID, 0, len(m.gws))
	for id := range m.gws {
		out = append(out, id)
	}
	return out
}

// ReportHealth sends the status of each tunnel when it changed or every call when not up.
func (m *Manager) ReportHealth(ctx context.Context, c *Client) {
	m.mu.Lock()
	list := make([]*gw, 0, len(m.gws))
	for _, g := range m.gws {
		list = append(list, g)
	}
	m.mu.Unlock()
	for _, g := range list {
		st, hs, msg := g.t.Health()
		if st == g.lastSt && st == vpn.StatusUp {
			continue
		}
		if err := c.TunnelStatus(ctx, g.id, st, hs, msg); err == nil {
			g.lastSt = st
		}
	}
}

// RunProxy is the SOCKS endpoint of one run (own byte counters, shared ceilings).
type RunProxy struct {
	Dir string
	srv *gateway.Server
	l   net.Listener
}

// OpenRun exposes the tunnel to one run through a unix socket in a private dir. The function has no other route to the customer network.
func (g *gw) OpenRun(root, runID string) (*RunProxy, error) {
	if len(runID) > 12 {
		runID = runID[:12] // keeps the unix socket path under the OS limit (108 bytes)
	}
	dir := filepath.Join(root, runID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "socks.sock")
	_ = os.Remove(sock)
	l, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(sock, 0o666) // only this run's container mounts the dir
	srv := gateway.NewServerWith(g.t, g.policy, g.limits)
	go srv.Serve(l)
	return &RunProxy{Dir: dir, srv: srv, l: l}, nil
}

// relayServer serves the relay's idle connections of this tunnel: same policy and shared ceilings as the per-run SOCKS endpoints.
func (g *gw) relayServer() *gateway.Server { return gateway.NewServerWith(g.t, g.policy, g.limits) }

// Bytes returns bytes received from (in) and sent to (out) the customer network by this run.
func (p *RunProxy) Bytes() (in, out int64) { return p.srv.Bytes() }

// Close drops the run's connections and removes its socket.
func (p *RunProxy) Close() {
	p.srv.CloseAll()
	_ = p.l.Close()
	_ = os.RemoveAll(p.Dir)
}

func (p *RunProxy) kill() { p.srv.CloseAll() }
