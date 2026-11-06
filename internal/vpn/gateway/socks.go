// Package gateway is the vpn-gateway: it owns a tunnel (the function never sees its credentials) and exposes it
// to the function container through a SOCKS5 endpoint (unix socket) that only dials the CIDRs declared for the tunnel.
package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Dialer opens connections inside the tunnel. There is deliberately no other path to any network.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Policy is the gateway's enforcement: declared networks only, connection and bandwidth ceilings.
type Policy struct {
	AllowedCIDRs []netip.Prefix
	MaxConns     int   // simultaneous connections through the tunnel; 0 = 4
	BandwidthBps int64 // aggregate bytes per second in both directions; 0 = unlimited
	DialTimeout  time.Duration
	OnDenied     func(target string, reason string) // audit hook
}

// Allowed reports whether ip is inside a declared network.
func (p Policy) Allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, c := range p.AllowedCIDRs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

// Server is a CONNECT-only SOCKS5 server without authentication (access control is the socket's file mode).
type Server struct {
	dial   Dialer
	policy Policy
	sem    chan struct{}
	lim    *rate.Limiter

	bytesIn, bytesOut atomic.Int64
	active            atomic.Int64

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
}

// Limits are the ceilings shared by every run that uses the same tunnel (connections and bandwidth), so several
// runs together never exceed what the customer's VPN was told it would get.
type Limits struct {
	sem chan struct{}
	lim *rate.Limiter
}

// NewLimits builds the shared ceilings of a tunnel.
func NewLimits(maxConns int, bandwidthBps int64) *Limits {
	if maxConns <= 0 {
		maxConns = 4
	}
	l := &Limits{sem: make(chan struct{}, maxConns)}
	if bandwidthBps > 0 {
		burst := int(bandwidthBps)
		if burst < 64<<10 {
			burst = 64 << 10
		}
		l.lim = rate.NewLimiter(rate.Limit(bandwidthBps), burst)
	}
	return l
}

// NewServer builds a Server with its own ceilings.
func NewServer(d Dialer, p Policy) *Server {
	return NewServerWith(d, p, NewLimits(p.MaxConns, p.BandwidthBps))
}

// NewServerWith builds a Server (one per run: own byte counters) on shared ceilings.
func NewServerWith(d Dialer, p Policy, l *Limits) *Server {
	if p.DialTimeout <= 0 {
		p.DialTimeout = 15 * time.Second
	}
	return &Server{dial: d, policy: p, sem: l.sem, lim: l.lim, conns: map[net.Conn]struct{}{}}
}

// Bytes returns the bytes sent into (out) and received from (in) the tunnel.
func (s *Server) Bytes() (in, out int64) { return s.bytesIn.Load(), s.bytesOut.Load() }

// Active returns the number of live proxied connections.
func (s *Server) Active() int64 { return s.active.Load() }

// Serve accepts connections until l is closed.
func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			s.wg.Wait()
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.track(c, true)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.track(c, false)
			s.handle(c)
		}()
	}
}

// CloseAll drops every live connection (kill switch).
func (s *Server) CloseAll() {
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
	s.mu.Unlock()
}

const (
	repOK          = 0x00
	repFail        = 0x01
	repNotAllowed  = 0x02
	repHostUnreach = 0x04
	repCmdNotSupp  = 0x07
	repAddrNotSupp = 0x08
)

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != 5 {
		return
	}
	if req[1] != 1 {
		reply(c, repCmdNotSupp)
		return
	}
	var ip netip.Addr
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		ip = netip.AddrFrom4([4]byte(b))
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		ip = netip.AddrFrom16([16]byte(b))
	default:
		// Names are not resolved on the host (that would touch host DNS); the SDK resolves inside the tunnel's declared networks by IP.
		reply(c, repAddrNotSupp)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)
	target := netip.AddrPortFrom(ip, port).String()
	if !s.policy.Allowed(ip) {
		if s.policy.OnDenied != nil {
			s.policy.OnDenied(target, "outside declared networks")
		}
		reply(c, repNotAllowed)
		return
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		if s.policy.OnDenied != nil {
			s.policy.OnDenied(target, "connection ceiling reached")
		}
		reply(c, repFail)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.policy.DialTimeout)
	up, err := s.dial.DialContext(ctx, "tcp", target)
	cancel()
	if err != nil {
		reply(c, repHostUnreach)
		return
	}
	s.track(up, true)
	defer s.track(up, false)
	defer up.Close()
	if reply(c, repOK) != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	s.active.Add(1)
	defer s.active.Add(-1)

	done := make(chan struct{}, 2)
	go func() { s.pipe(up, c, &s.bytesOut); _ = up.Close(); done <- struct{}{} }()
	go func() { s.pipe(c, up, &s.bytesIn); _ = c.Close(); done <- struct{}{} }()
	<-done
	<-done
}

func reply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func (s *Server) pipe(dst io.Writer, src io.Reader, ctr *atomic.Int64) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if s.lim != nil {
				if werr := s.lim.WaitN(context.Background(), n); werr != nil {
					return
				}
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
			ctr.Add(int64(n))
		}
		if err != nil {
			return
		}
	}
}

// ParsePolicyCIDRs converts declared CIDR strings.
func ParsePolicyCIDRs(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("cidr %q: %w", c, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
