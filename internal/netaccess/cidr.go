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
	// MinPrefixV6 is the widest IPv6 prefix accepted for any rule (/32, the size of
	// a typical ISP allocation; anything wider is effectively "the internet").
	MinPrefixV6 = 32
	// PublicCIDR is the IPv4 "open to the world" CIDR; it needs explicit opt-in.
	PublicCIDR = "0.0.0.0/0"
	// PublicCIDRv6 is the IPv6 "open to the world" CIDR (same opt-in as PublicCIDR).
	PublicCIDRv6 = "::/0"
	// MaxRulesPerDatabase is the maximum number of access rules per database.
	MaxRulesPerDatabase = 25
	// MaxAllowlistEntries is the maximum number of entries in a project IP allowlist.
	MaxAllowlistEntries = 50
)

var (
	ErrInvalidCIDR = errors.New("invalid CIDR")
	ErrPublicCIDR  = errors.New("public access requires allow_public")
)

// NormalizeCIDR validates an IPv4 or IPv6 CIDR (a bare address is treated as
// /32 or /128) and returns its canonical form: host bits cleared, IPv6 in the
// compressed lowercase form (RFC 5952), e.g. 10.1.2.3/24 -> 10.1.2.0/24 and
// 2001:DB8:0:0::1 -> 2001:db8::1/128.
//
//   - An IPv4-mapped address (::ffff:a.b.c.d) is treated as the IPv4 address.
//     A mapped prefix shorter than /96 is rejected (it would not be a pure IPv4 range).
//   - Zone identifiers ("fe80::1%eth0") are rejected.
//   - IPv4 prefixes shorter than /8 and IPv6 prefixes shorter than /32 are always
//     rejected, except the /0 of each family, which canonicalises to PublicCIDR /
//     PublicCIDRv6 and is rejected unless allowPublic is true.
func NormalizeCIDR(raw string, allowPublic bool) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("%w: empty value", ErrInvalidCIDR)
	}
	if strings.Contains(s, "%") {
		return "", fmt.Errorf("%w: zone identifiers are not allowed (%q)", ErrInvalidCIDR, raw)
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
	if addr.Is4In6() {
		if prefix.Bits() < 96 {
			return "", fmt.Errorf("%w: IPv4-mapped prefix must be /96 or longer (%q)", ErrInvalidCIDR, raw)
		}
		prefix = netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96)
		addr = prefix.Addr()
	}
	if addr.Is4() {
		if prefix.Bits() == 0 {
			if !allowPublic {
				return "", fmt.Errorf("%w: %s", ErrPublicCIDR, PublicCIDR)
			}
			return PublicCIDR, nil
		}
		if prefix.Bits() < MinPrefix {
			return "", fmt.Errorf("%w: IPv4 prefix must be /%d or longer (%q)", ErrInvalidCIDR, MinPrefix, raw)
		}
		return prefix.Masked().String(), nil
	}
	if prefix.Bits() == 0 {
		if !allowPublic {
			return "", fmt.Errorf("%w: %s", ErrPublicCIDR, PublicCIDRv6)
		}
		return PublicCIDRv6, nil
	}
	if prefix.Bits() < MinPrefixV6 {
		return "", fmt.Errorf("%w: IPv6 prefix must be /%d or longer (%q)", ErrInvalidCIDR, MinPrefixV6, raw)
	}
	return prefix.Masked().String(), nil
}

// IsPublicCIDR reports whether c is the "whole internet" CIDR of either family.
func IsPublicCIDR(c string) bool { return c == PublicCIDR || c == PublicCIDRv6 }

// IsIPv6CIDR reports whether the (canonical) CIDR belongs to the IPv6 family.
func IsIPv6CIDR(c string) bool {
	p, err := netip.ParsePrefix(strings.TrimSpace(c))
	return err == nil && p.Addr().Is6() && !p.Addr().Is4In6()
}

// SameCIDR compares two CIDRs by value (so "2001:DB8::/32" equals "2001:db8::/32").
func SameCIDR(a, b string) bool {
	if a == b {
		return true
	}
	pa, ea := netip.ParsePrefix(a)
	pb, eb := netip.ParsePrefix(b)
	return ea == nil && eb == nil && pa.Masked() == pb.Masked()
}

// ParseIP parses a client address (IPv4, IPv6, IPv4-mapped, optional zone) into
// its canonical form: mapped addresses become IPv4 and zones are dropped.
func ParseIP(ip string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.WithZone("").Unmap(), true
}

// ContainsIP reports whether ip is inside any of the CIDRs (both families are
// compared by prefix; an IPv4-mapped IPv6 address matches IPv4 entries).
// Invalid entries are ignored.
func ContainsIP(cidrs []string, ip string) bool {
	addr, ok := ParseIP(ip)
	if !ok {
		return false
	}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		if p.Addr().Is4In6() { // a stored mapped prefix is an IPv4 prefix
			if p.Bits() < 96 {
				continue
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
