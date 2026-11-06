package fnagent

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/fn"
)

// Relay (docs/vpn-connector.md, section 7): for a Lambda run the node keeps its tunnel up and offers idle connections to the
// Capsule API, outbound only. The API pairs one with each connection a function asks for; the node dials inside the tunnel
// after enforcing the declared networks and the shared ceilings again.

// relayIdle is how many idle connections the node keeps offered per tunnel.
const relayIdle = 4

// bufConn keeps what the HTTP reader already buffered after the 101 response.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// RelayOffer opens one idle relay connection for the tunnel: an HTTP upgrade to the API authenticated with the node token.
// It returns when the API has accepted it; the connection then waits until the API uses it.
func (c *Client) RelayOffer(ctx context.Context, tunnel uuid.UUID) (net.Conn, error) {
	u, err := url.Parse(strings.TrimRight(c.Base, "/"))
	if err != nil {
		return nil, err
	}
	host := u.Host
	d := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	switch u.Scheme {
	case "https":
		if !strings.Contains(host, ":") {
			host += ":443"
		}
		conn, err = (&tls.Dialer{NetDialer: &d, Config: &tls.Config{ServerName: u.Hostname()}}).DialContext(ctx, "tcp", host)
	default:
		if !strings.Contains(host, ":") {
			host += ":80"
		}
		conn, err = d.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	_, err = fmt.Fprintf(conn, "POST %s/api/v1/fn/relay/node/%s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nConnection: Upgrade\r\nUpgrade: capsule-relay\r\nContent-Length: 0\r\n\r\n",
		u.Path, tunnel, u.Host, c.Token)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return nil, fmt.Errorf("relay offer refused: %d", resp.StatusCode)
	}
	_ = conn.SetDeadline(time.Time{})
	return bufConn{conn, br}, nil
}

// relays keeps the idle connection workers of the tunnels the API assigned to this node.
type relays struct {
	mu      sync.Mutex
	workers map[uuid.UUID]context.CancelFunc
}

// syncRelays starts workers for the tunnels in want (opening their gateways) and stops those no longer wanted.
func (a *Agent) syncRelays(ctx context.Context, want []fn.TunnelAssignment) {
	a.rl.mu.Lock()
	defer a.rl.mu.Unlock()
	if a.rl.workers == nil {
		a.rl.workers = map[uuid.UUID]context.CancelFunc{}
	}
	in := map[uuid.UUID]bool{}
	for _, ta := range want {
		in[ta.ID] = true
		if _, ok := a.rl.workers[ta.ID]; ok {
			continue
		}
		if _, err := a.Mgr.Ensure(ta); err != nil {
			a.log().Warn("relay tunnel could not be opened", "tunnel", ta.ID, "error", err)
			continue
		}
		wctx, cancel := context.WithCancel(ctx)
		a.rl.workers[ta.ID] = cancel
		for i := 0; i < relayIdle; i++ {
			go a.relayWorker(wctx, ta)
		}
	}
	for id, cancel := range a.rl.workers {
		if !in[id] {
			cancel()
			delete(a.rl.workers, id)
		}
	}
}

func (a *Agent) relayWorker(ctx context.Context, ta fn.TunnelAssignment) {
	backoff := time.Second
	for ctx.Err() == nil {
		g, err := a.Mgr.Ensure(ta) // follows a restarted gateway (changed credentials or networks)
		if err != nil {
			sleepCtx(ctx, backoff)
			continue
		}
		conn, err := a.Client.RelayOffer(ctx, ta.ID)
		if err != nil {
			if ctx.Err() == nil {
				a.log().Warn("relay offer failed", "tunnel", ta.ID, "error", err)
			}
			sleepCtx(ctx, backoff)
			if backoff < 15*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		g.relayServer().ServeRelay(conn) // returns once this connection has been used up (or dropped)
		stop()
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
