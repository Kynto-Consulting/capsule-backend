package netaccess

import (
	"net"
	"net/netip"
	"strings"
)

// ClientIP returns the best-effort real client IP.
//
// Capsule runs behind an ALB, which APPENDS the address it saw to
// X-Forwarded-For; everything to the left of that is client-controlled and can
// be spoofed. We therefore walk the header from the RIGHT, skipping addresses
// that belong to our own infrastructure (private, loopback, link-local: the
// ALB itself, the frontend container), and return the first public address.
// If every entry is private the right-most valid one is returned (internal
// callers). Without a usable header, remoteAddr (without port) is used.
//
// remoteAddr must be the ORIGINAL socket address (see middleware.CaptureRemoteAddr),
// not the one rewritten by chi's RealIP middleware, which trusts client headers.
func ClientIP(remoteAddr, xff string) string {
	var lastValid string
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			continue // not an address: cannot have been appended by the ALB
		}
		a = a.Unmap()
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
	host := strings.TrimSpace(remoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().String()
	}
	return host
}

func isInfra(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified()
}
