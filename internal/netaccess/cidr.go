// Package netaccess holds the network-access logic of Capsule: CIDR validation,
// trusted client-IP extraction and the reconciler that applies per-database
// access rules to the app host's EC2 security group.
package netaccess

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	// MinPrefix is the widest IPv4 prefix accepted for any rule (/8).
	MinPrefix = 8
	// PublicCIDR is the "open to the world" CIDR; it needs explicit opt-in.
	PublicCIDR = "0.0.0.0/0"
	// MaxRulesPerDatabase is the maximum number of access rules per database.
	MaxRulesPerDatabase = 25
	// MaxAllowlistEntries is the maximum number of entries in a project IP allowlist.
	MaxAllowlistEntries = 50
)

var (
	ErrInvalidCIDR = errors.New("invalid CIDR")
	ErrPublicCIDR  = errors.New("public access requires allow_public")
)

// NormalizeCIDR validates an IPv4 CIDR (a bare address is treated as /32) and
// returns its canonical form (host bits cleared, e.g. 10.1.2.3/24 -> 10.1.2.0/24).
// Prefixes shorter than /8 are always rejected. 0.0.0.0/0 is rejected unless
// allowPublic is true.
func NormalizeCIDR(raw string, allowPublic bool) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("%w: empty value", ErrInvalidCIDR)
	}
	var prefix netip.Prefix
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", fmt.Errorf("%w: %q", ErrInvalidCIDR, raw)
		}
		prefix = p
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return "", fmt.Errorf("%w: %q", ErrInvalidCIDR, raw)
		}
		prefix = netip.PrefixFrom(a, a.BitLen())
	}
	addr := prefix.Addr()
	if !addr.Is4() {
		return "", fmt.Errorf("%w: only IPv4 is supported (%q)", ErrInvalidCIDR, raw)
	}
	if prefix.Bits() == 0 {
		if !allowPublic {
			return "", fmt.Errorf("%w: %s", ErrPublicCIDR, PublicCIDR)
		}
		return PublicCIDR, nil
	}
	if prefix.Bits() < MinPrefix {
		return "", fmt.Errorf("%w: prefix must be /%d or longer (%q)", ErrInvalidCIDR, MinPrefix, raw)
	}
	return prefix.Masked().String(), nil
}

// ContainsIP reports whether ip is inside any of the CIDRs. Invalid entries are ignored.
func ContainsIP(cidrs []string, ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
