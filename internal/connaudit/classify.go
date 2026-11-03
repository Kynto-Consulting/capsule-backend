// Package connaudit detects connections from a deployment to Capsule's internal
// servers that are not routed through the gateway protocol (published host
// ports, loopback, docker bridge, container names, private networks, the cloud
// metadata service). It is pure: no database, no network, no new dependencies.
//
// Secret values are analysed in memory only. A Finding carries the NAME of the
// variable or the file:line, and an endpoint stripped of credentials, path and
// query; nothing else of the input ever leaves this package.
package connaudit

import (
	"net/netip"
	"os"
	"strings"
)

// Kind classifies an endpoint.
type Kind string

const (
	KindDirectPort   Kind = "INTERNAL_DIRECT_PORT"
	KindLoopback     Kind = "LOOPBACK"
	KindDockerBridge Kind = "DOCKER_BRIDGE"
	KindContainer    Kind = "CAPSULE_CONTAINER"
	KindPrivate      Kind = "PRIVATE_NETWORK"
	KindMetadata     Kind = "METADATA"
	KindOK           Kind = "OK"
)

// Severity of a finding.
type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
)

// Rank orders severities (info < warning < critical).
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 2
	case SevWarning:
		return 1
	}
	return 0
}

// Classifier decides what an endpoint is. The zero value is usable: it knows
// loopback, docker, private and metadata ranges and the default port range.
type Classifier struct {
	DirectHosts    []string        // db.tumi-ai.com, CAPSULE_DB_HOST, CAPSULE_TCP_HOST
	DirectIPs      []string        // elastic IP of the host
	GatewayDomains []string        // db.tumi-ai.com, apps.tumi-ai.com (the "*." is implied)
	PortFrom       int             // published range, default 40000
	PortTo         int             // default 41999
	Published      func(int) bool  // other ports Capsule publishes
	OwnShort       string          // 12-hex short id of the project being deployed
	OwnNames       map[string]bool // container names that belong to this project
}

// ClassifierFromEnv builds a Classifier from the Capsule environment:
// CAPSULE_DB_HOST, CAPSULE_TCP_HOST, CAPSULE_PUBLIC_HOST, CAPSULE_ELASTIC_IP,
// CAPSULE_GATEWAY_DOMAINS (comma separated, "*." optional).
func ClassifierFromEnv() *Classifier {
	c := &Classifier{DirectHosts: []string{"db.tumi-ai.com"}}
	for _, k := range []string{"CAPSULE_DB_HOST", "CAPSULE_TCP_HOST", "CAPSULE_PUBLIC_HOST"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			c.addDirect(v)
		}
	}
	if v := strings.TrimSpace(os.Getenv("CAPSULE_ELASTIC_IP")); v != "" {
		c.addDirect(v)
	}
	gw := os.Getenv("CAPSULE_GATEWAY_DOMAINS")
	if strings.TrimSpace(gw) == "" {
		gw = "*.db.tumi-ai.com,*.apps.tumi-ai.com"
	}
	for _, d := range strings.Split(gw, ",") {
		d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "*.")
		if d != "" {
			c.GatewayDomains = append(c.GatewayDomains, d)
		}
	}
	return c
}

func (c *Classifier) addDirect(h string) {
	h = normHost(h)
	if h == "" {
		return
	}
	if _, err := netip.ParseAddr(h); err == nil {
		c.DirectIPs = append(c.DirectIPs, h)
		return
	}
	c.DirectHosts = append(c.DirectHosts, h)
}

func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")
	h = strings.TrimSuffix(h, ".")
	if i := strings.IndexByte(h, '%'); i >= 0 && strings.Contains(h, ":") { // IPv6 zone
		h = h[:i]
	}
	return h
}

func (c *Classifier) inRange(port int) bool {
	from, to := c.PortFrom, c.PortTo
	if from == 0 {
		from = 40000
	}
	if to == 0 {
		to = 41999
	}
	if port >= from && port <= to {
		return true
	}
	return c.Published != nil && port > 0 && c.Published(port)
}

func (c *Classifier) isGateway(h string) bool {
	h = strings.TrimPrefix(h, "*.")
	for _, d := range c.GatewayDomains {
		if strings.HasSuffix(h, "."+d) || (h == d && !c.isDirectHost(h)) {
			return true
		}
	}
	return false
}

func (c *Classifier) isDirectHost(h string) bool {
	for _, d := range c.DirectHosts {
		if h == d {
			return true
		}
	}
	return false
}

func (c *Classifier) isDirectIP(a netip.Addr) bool {
	for _, d := range c.DirectIPs {
		if p, err := netip.ParseAddr(d); err == nil && p.Unmap() == a {
			return true
		}
	}
	return false
}

var (
	cgnat     = netip.MustParsePrefix("100.64.0.0/10")
	dockerNet = netip.MustParsePrefix("172.16.0.0/12")
	metaV4    = netip.MustParseAddr("169.254.169.254")
	metaECS   = netip.MustParseAddr("169.254.170.2")
	metaV6    = netip.MustParseAddr("fd00:ec2::254")
)

// Classify returns the kind and severity of host:port (port 0 = unknown).
// Hostnames with unresolved placeholders ($VAR, {{x}}) classify as OK.
func (c *Classifier) Classify(host string, port int) (Kind, Severity) {
	h := normHost(host)
	if h == "" || strings.ContainsAny(h, "$<>{}") || h == "*" {
		return KindOK, SevInfo
	}
	if c.isGateway(h) {
		return KindOK, SevInfo
	}
	if c.isDirectHost(h) {
		if port == 80 || port == 443 {
			return KindOK, SevInfo
		}
		return KindDirectPort, SevWarning
	}
	if a, err := netip.ParseAddr(h); err == nil {
		a = a.Unmap()
		switch {
		case a == metaV4 || a == metaV6 || a == metaECS:
			return KindMetadata, SevCritical
		case a.IsUnspecified():
			return KindOK, SevInfo // listen address, not a destination
		case a.IsLoopback():
			if c.inRange(port) {
				return KindDirectPort, SevWarning
			}
			return KindLoopback, SevWarning
		case c.isDirectIP(a):
			if port == 80 || port == 443 {
				return KindOK, SevInfo
			}
			return KindDirectPort, SevWarning
		case a.Is4() && dockerNet.Contains(a):
			return KindDockerBridge, SevWarning
		case a.IsPrivate(), a.IsLinkLocalUnicast(), a.Is4() && cgnat.Contains(a):
			return KindPrivate, SevInfo
		}
		return KindOK, SevInfo
	}
	switch {
	case h == "localhost" || strings.HasSuffix(h, ".localhost"):
		if c.inRange(port) {
			return KindDirectPort, SevWarning
		}
		return KindLoopback, SevWarning
	case h == "host.docker.internal" || h == "gateway.docker.internal" || h == "host.containers.internal":
		return KindDockerBridge, SevWarning
	case strings.HasPrefix(h, "capsule-") || strings.HasPrefix(h, "capsule_"):
		first := h
		if i := strings.IndexByte(h, '.'); i >= 0 {
			first = h[:i]
		}
		if c.isOwn(first) {
			return KindContainer, SevWarning
		}
		return KindContainer, SevCritical
	case strings.HasSuffix(h, ".ec2.internal") || strings.HasSuffix(h, ".compute.internal"):
		return KindPrivate, SevInfo
	}
	return KindOK, SevInfo
}

func (c *Classifier) isOwn(name string) bool {
	if c.OwnNames[name] {
		return true
	}
	return c.OwnShort != "" && (name == "capsule-app-"+c.OwnShort || strings.HasPrefix(name, "capsule-app-"+c.OwnShort+"-"))
}
