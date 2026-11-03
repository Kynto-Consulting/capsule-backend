package netaccess

import (
	"net"
	"net/netip"
	"strings"
)

// ClientIP returns the best-effort real client IP (IPv4 or IPv6, canonical).
//
// Capsule runs behind an ALB, which APPENDS the address it saw to
// X-Forwarded-For (a dualstack ALB appends the client's IPv6 address when the
// client connected over IPv6); everything to the left of that is
// client-controlled and can be spoofed. We therefore walk the header from the
// RIGHT, skipping addresses that belong to our own infrastructure (private,
// ULA fc00::/7, loopback, link-local, multicast, unspecified: the ALB itself,
// the frontend container), and return the first public address. If every entry
// is private the right-most valid one is returned (internal callers). Without
// a usable header, remoteAddr (without port) is used.
//
// Entries may be written as "1.2.3.4", "1.2.3.4:5", "2001:db8::1",
// "[2001:db8::1]" or "[2001:db8::1]:443"; IPv4-mapped addresses are unmapped
// and zones dropped.
//
// remoteAddr must be the ORIGINAL socket address (see middleware.CaptureRemoteAddr),
// not the one rewritten by chi's RealIP middleware, which trusts client headers.
func ClientIP(remoteAddr, xff string) string {
	var lastValid string
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, ok := parseHostAddr(parts[i])
		if !ok {
			continue // not an address: cannot have been appended by the ALB
		}
		if lastValid == "" {
			lastValid = a.String()
		}
		if !isInfra(a) {
			return a.String()
		}
	}
	if lastValid != "" {
		return lastValid
	}
	if a, ok := parseHostAddr(remoteAddr); ok {
		return a.String()
	}
	return strings.TrimSpace(remoteAddr)
}

// parseHostAddr parses "ip", "ip:port", "[ip]" or "[ip]:port".
func parseHostAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, false
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	} else if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	return ParseIP(s)
}

func isInfra(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified()
}
