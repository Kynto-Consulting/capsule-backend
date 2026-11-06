package gateway

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The relay lets a function that cannot run next to the tunnel (an AWS Lambda without VPC/NAT) reach it.
//
//	Lambda --(HTTPS upgrade, run token)--> Capsule API (Relay) <--(HTTPS upgrade, node token, outbound)-- work node --> tunnel
//
// The work node that owns the tunnel keeps a few idle connections open towards the API (Offer). A function's connection is
// paired with one of them: the relay checks the destination against the declared CIDRs (and audits denials), asks the node
// to dial it, and then only splices bytes. The node enforces the same policy and the shared ceilings again. Neither the
// function nor the relay ever sees the tunnel's credentials; no inbound port is opened anywhere.

// Relay errors.
var (
	ErrRelayDenied     = errors.New("relay: destination outside the declared networks")
	ErrRelayNoNode     = errors.New("relay: the tunnel's node is not attached")
	ErrRelayRefused    = errors.New("relay: the node could not reach the destination")
	ErrRelayCeiling    = errors.New("relay: connection ceiling reached")
	ErrRelayBadRequest = errors.New("relay: destination must be ip:port")
)

// Replies of the node to a CONNECT line.
const (
	relayOK      = 0
	relayFail    = 1
	relayDenied  = 2
	relayCeiling = 3
)

// Relay is the API-side rendezvous. The zero value is not usable; use NewRelay.
type Relay struct {
	// Wait is how long Open waits for an idle node connection (default 10 s).
	Wait time.Duration

	mu   sync.Mutex
	idle map[string]chan net.Conn // tunnel id -> idle node connections
	runs map[string]*relayRun
}

type relayRun struct {
	in, out atomic.Int64
	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closed  bool
}

// NewRelay creates an empty relay.
func NewRelay() *Relay {
	return &Relay{idle: map[string]chan net.Conn{}, runs: map[string]*relayRun{}}
}

const idlePool = 16

func (r *Relay) pool(tunnel string) chan net.Conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch, ok := r.idle[tunnel]
	if !ok {
		ch = make(chan net.Conn, idlePool)
		r.idle[tunnel] = ch
	}
	return ch
}

// Offer stores an idle connection that a work node opened for the tunnel. It is closed when the pool is full.
func (r *Relay) Offer(tunnel string, c net.Conn) {
	select {
	case r.pool(tunnel) <- c:
	default:
		_ = c.Close()
	}
}

// Idle returns how many idle node connections the tunnel has (a function waits for at least one before it starts).
func (r *Relay) Idle(tunnel string) int { return len(r.pool(tunnel)) }

// Open pairs a destination with an idle node connection and returns it connected to dest. policy is the tunnel's
// declared networks; a destination outside them is denied (and reported through policy.OnDenied) before any node is asked.
func (r *Relay) Open(ctx context.Context, tunnel, dest string, policy Policy) (net.Conn, error) {
	ap, err := netip.ParseAddrPort(dest)
	if err != nil {
		return nil, ErrRelayBadRequest
	}
	if !policy.Allowed(ap.Addr()) {
		if policy.OnDenied != nil {
			policy.OnDenied(ap.String(), "outside declared networks (relay)")
		}
		return nil, ErrRelayDenied
	}
	wait := r.Wait
	if wait <= 0 {
		wait = 10 * time.Second
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	ch := r.pool(tunnel)
	for {
		var c net.Conn
		select {
		case c = <-ch:
		case <-timer.C:
			return nil, ErrRelayNoNode
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		code, err := askNode(c, ap.String())
		if err != nil { // a stale idle connection: try the next one
			_ = c.Close()
			continue
		}
		switch code {
		case relayOK:
			return c, nil
		case relayDenied:
			_ = c.Close()
			if policy.OnDenied != nil {
				policy.OnDenied(ap.String(), "denied by the node")
			}
			return nil, ErrRelayDenied
		case relayCeiling:
			_ = c.Close()
			if policy.OnDenied != nil {
				policy.OnDenied(ap.String(), "connection ceiling reached (relay)")
			}
			return nil, ErrRelayCeiling
		default:
			_ = c.Close()
			return nil, ErrRelayRefused
		}
	}
}

func askNode(c net.Conn, dest string) (byte, error) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := io.WriteString(c, "CONNECT "+dest+"\n"); err != nil {
		return 0, err
	}
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *Relay) run(id string) *relayRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	rr, ok := r.runs[id]
	if !ok {
		rr = &relayRun{conns: map[net.Conn]struct{}{}}
		r.runs[id] = rr
	}
	return rr
}

// Splice copies bytes between the function's connection and the node's until either ends, counting them for the run.
// The ceiling on bandwidth is the node's (it shares the tunnel's Limits with every other user of the tunnel).
func (r *Relay) Splice(runID string, fn, node net.Conn) {
	rr := r.run(runID)
	rr.mu.Lock()
	if rr.closed {
		rr.mu.Unlock()
		_ = fn.Close()
		_ = node.Close()
		return
	}
	rr.conns[fn], rr.conns[node] = struct{}{}, struct{}{}
	rr.mu.Unlock()
	defer func() {
		rr.mu.Lock()
		delete(rr.conns, fn)
		delete(rr.conns, node)
		rr.mu.Unlock()
		_ = fn.Close()
		_ = node.Close()
	}()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(&countWriter{node, &rr.out}, fn); _ = node.Close(); done <- struct{}{} }()
	go func() { _, _ = io.Copy(&countWriter{fn, &rr.in}, node); _ = fn.Close(); done <- struct{}{} }()
	<-done
	<-done
}

// Bytes returns bytes received from (in) and sent to (out) the customer network by the run.
func (r *Relay) Bytes(runID string) (in, out int64) {
	r.mu.Lock()
	rr := r.runs[runID]
	r.mu.Unlock()
	if rr == nil {
		return 0, 0
	}
	return rr.in.Load(), rr.out.Load()
}

// CloseRun drops every live connection of a run and refuses new ones (run ended, cancelled or kill switch).
func (r *Relay) CloseRun(runID string) {
	r.mu.Lock()
	rr := r.runs[runID]
	r.mu.Unlock()
	if rr == nil {
		return
	}
	rr.mu.Lock()
	rr.closed = true
	for c := range rr.conns {
		_ = c.Close()
	}
	rr.mu.Unlock()
}

// Forget removes the counters of a finished run.
func (r *Relay) Forget(runID string) {
	r.mu.Lock()
	delete(r.runs, runID)
	r.mu.Unlock()
}

// DropTunnel closes the idle connections of a tunnel (kill switch).
func (r *Relay) DropTunnel(tunnel string) {
	ch := r.pool(tunnel)
	for {
		select {
		case c := <-ch:
			_ = c.Close()
		default:
			return
		}
	}
}

// ServeRelay is the node side: it serves one idle connection. It waits for a "CONNECT ip:port" line, enforces the policy and
// the tunnel's shared ceilings, dials inside the tunnel and then pipes bytes. It returns when the connection is used up.
func (s *Server) ServeRelay(c net.Conn) {
	defer c.Close()
	s.track(c, true)
	defer s.track(c, false)
	br := bufio.NewReaderSize(c, 256)
	line, err := br.ReadString('\n') // idle: no deadline, the API closes or uses it
	if err != nil || len(line) > 200 {
		return
	}
	dest, ok := strings.CutPrefix(strings.TrimSpace(line), "CONNECT ")
	ap, perr := netip.ParseAddrPort(dest)
	if !ok || perr != nil {
		_, _ = c.Write([]byte{relayFail})
		return
	}
	target := ap.String()
	if !s.policy.Allowed(ap.Addr()) {
		if s.policy.OnDenied != nil {
			s.policy.OnDenied(target, "outside declared networks")
		}
		_, _ = c.Write([]byte{relayDenied})
		return
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		if s.policy.OnDenied != nil {
			s.policy.OnDenied(target, "connection ceiling reached")
		}
		_, _ = c.Write([]byte{relayCeiling})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.policy.DialTimeout)
	up, err := s.dial.DialContext(ctx, "tcp", target)
	cancel()
	if err != nil {
		_, _ = c.Write([]byte{relayFail})
		return
	}
	s.track(up, true)
	defer s.track(up, false)
	defer up.Close()
	if _, err := c.Write([]byte{relayOK}); err != nil {
		return
	}
	s.active.Add(1)
	defer s.active.Add(-1)
	var src io.Reader = c
	if br.Buffered() > 0 {
		src = io.MultiReader(io.LimitReader(br, int64(br.Buffered())), c)
	}
	done := make(chan struct{}, 2)
	go func() { s.pipe(up, src, &s.bytesOut); _ = up.Close(); done <- struct{}{} }()
	go func() { s.pipe(c, up, &s.bytesIn); _ = c.Close(); done <- struct{}{} }()
	<-done
	<-done
}

// countWriter counts bytes as they are written, so a long transfer is visible while it runs.
type countWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}
