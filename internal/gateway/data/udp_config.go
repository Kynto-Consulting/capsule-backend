package data

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// UDPConfig tunes the UDP-over-stream tunnel (capsule/1 transport 2, PROTOCOL.md section 10).
type UDPConfig struct {
	TunnelDisabled     bool          // refuse transport 2 with 1/0x0109 (default: served)
	IdleTimeout        time.Duration // inactivity limit of a session (60 s)
	KeepaliveInterval  time.Duration // keepalive sent to the client when nothing was sent (IdleTimeout/3)
	MaxDatagram        int           // largest datagram forwarded (2048, the protocol maximum); announced in CAPR
	QueueBytes         int           // destination-to-client queue per session (256 KiB); beyond it datagrams are dropped
	MaxSessionsRoute   int           // concurrent UDP sessions per route (50)
	MaxSessionsIP      int           // per route and source IP (10)
	MaxSessionsProject int           // per project (50, PROTOCOL.md 10.4)
}

// PoolConfig tunes the random-port listeners (PLAN.md 3.4): the gateway listens on the leased ports of the route
// table, TCP as passthrough and UDP as a NAT table with one flow per client address.
type PoolConfig struct {
	Disabled     bool
	Min, Max     int           // ports outside this range are never bound (20000-29999)
	Bind         string        // address the listeners bind to ("[::]" = dual stack)
	DrainTimeout time.Duration // how long connections/flows of a released lease may continue (10 min)
	FlowIdle     time.Duration // inactivity limit of a UDP flow (60 s)
	Revalidate   time.Duration // an established UDP flow is authorised again after this long (30 s)
	MaxFlows     int           // hard cap of UDP flows per leased port (2048)
	NewFlowRate  float64       // new UDP flows admitted per second per leased port, before any per-IP state (100)
}

const (
	defaultPoolMin = 20000
	defaultPoolMax = 29999
)

func (u *UDPConfig) fill() {
	if u.IdleTimeout <= 0 {
		u.IdleTimeout = 60 * time.Second
	}
	if u.KeepaliveInterval <= 0 {
		u.KeepaliveInterval = u.IdleTimeout / 3
	}
	if u.MaxDatagram <= 0 || u.MaxDatagram > maxUDPDatagram {
		u.MaxDatagram = maxUDPDatagram
	}
	if u.QueueBytes <= 0 {
		u.QueueBytes = 256 << 10
	}
	if u.MaxSessionsRoute <= 0 {
		u.MaxSessionsRoute = 50
	}
	if u.MaxSessionsIP <= 0 {
		u.MaxSessionsIP = 10
	}
	if u.MaxSessionsProject <= 0 {
		u.MaxSessionsProject = 50
	}
}

func (p *PoolConfig) fill() {
	if p.Min == 0 && p.Max == 0 {
		p.Min, p.Max = defaultPoolMin, defaultPoolMax
	}
	if p.Bind == "" {
		p.Bind = "[::]"
	}
	if p.DrainTimeout <= 0 {
		p.DrainTimeout = 10 * time.Minute
	}
	if p.FlowIdle <= 0 {
		p.FlowIdle = 60 * time.Second
	}
	if p.Revalidate <= 0 {
		p.Revalidate = 30 * time.Second
	}
	if p.MaxFlows <= 0 {
		p.MaxFlows = 2048
	}
	if p.NewFlowRate <= 0 {
		p.NewFlowRate = 100
	}
}

// parsePoolRange parses "lo-hi" or "off".
func parsePoolRange(s string) (lo, hi int, off bool, err error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "none", "0", "disabled":
		return 0, 0, true, nil
	}
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, false, fmt.Errorf("want lo-hi")
	}
	lo, e1 := strconv.Atoi(strings.TrimSpace(a))
	hi, e2 := strconv.Atoi(strings.TrimSpace(b))
	if e1 != nil || e2 != nil || lo < 1024 || hi > 65535 || lo > hi {
		return 0, 0, false, fmt.Errorf("want lo-hi inside 1024-65535")
	}
	return lo, hi, false, nil
}

// applyUDPEnv overlays the CAPSULE_GW_UDP_* and CAPSULE_GW_POOL* variables and returns the errors found.
func applyUDPEnv(c *Config, getenv func(string) string) []string {
	var errs []string
	dur := func(name string, dst *time.Duration) {
		if v := getenv(name); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				errs = append(errs, name+": "+err.Error())
				return
			}
			*dst = d
		}
	}
	num := func(name string, dst *int) {
		if v := getenv(name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				errs = append(errs, name+": "+err.Error())
				return
			}
			*dst = n
		}
	}
	if v := getenv("CAPSULE_GW_UDP_TUNNEL"); v != "" {
		switch strings.ToLower(v) {
		case "off", "false", "0", "disabled":
			c.UDP.TunnelDisabled = true
		}
	}
	dur("CAPSULE_GW_UDP_IDLE", &c.UDP.IdleTimeout)
	dur("CAPSULE_GW_UDP_KEEPALIVE", &c.UDP.KeepaliveInterval)
	num("CAPSULE_GW_UDP_MAX_DATAGRAM", &c.UDP.MaxDatagram)
	num("CAPSULE_GW_UDP_QUEUE_BYTES", &c.UDP.QueueBytes)
	num("CAPSULE_GW_UDP_SESSIONS_ROUTE", &c.UDP.MaxSessionsRoute)
	num("CAPSULE_GW_UDP_SESSIONS_IP", &c.UDP.MaxSessionsIP)
	num("CAPSULE_GW_UDP_SESSIONS_PROJECT", &c.UDP.MaxSessionsProject)
	if v := getenv("CAPSULE_GW_POOL"); v != "" {
		lo, hi, off, err := parsePoolRange(v)
		switch {
		case err != nil:
			errs = append(errs, "CAPSULE_GW_POOL: "+err.Error())
		case off:
			c.Pool.Disabled = true
		default:
			c.Pool.Min, c.Pool.Max = lo, hi
		}
	}
	if v := getenv("CAPSULE_GW_POOL_BIND"); v != "" {
		c.Pool.Bind = v
	}
	dur("CAPSULE_GW_POOL_DRAIN", &c.Pool.DrainTimeout)
	dur("CAPSULE_GW_POOL_FLOW_IDLE", &c.Pool.FlowIdle)
	dur("CAPSULE_GW_POOL_REVALIDATE", &c.Pool.Revalidate)
	num("CAPSULE_GW_POOL_MAX_FLOWS", &c.Pool.MaxFlows)
	if v := getenv("CAPSULE_GW_POOL_FLOW_RATE"); v != "" {
		n, err := strconv.ParseFloat(v, 64)
		if err != nil {
			errs = append(errs, "CAPSULE_GW_POOL_FLOW_RATE: "+err.Error())
		} else {
			c.Pool.NewFlowRate = n
		}
	}
	return errs
}
