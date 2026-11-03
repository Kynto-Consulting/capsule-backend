// Package gitsource fetches code from Git remotes safely: URL validation with
// SSRF protection, hardened clone, tarball packaging, webhook verification and
// provider API clients (commit statuses and PR comments).
package gitsource

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// LookupFunc resolves a host to IPs (injectable for tests).
type LookupFunc func(ctx context.Context, host string) ([]net.IP, error)

// Policy decides which repositories may be contacted.
type Policy struct {
	// AllowedHosts restricts hosts (exact, case-insensitive). Empty = any public host.
	AllowedHosts []string
	Lookup       LookupFunc // nil = system resolver
}

// PolicyFromEnv reads CAPSULE_GIT_ALLOWED_HOSTS (comma-separated).
func PolicyFromEnv() Policy {
	var hosts []string
	for _, h := range strings.Split(os.Getenv("CAPSULE_GIT_ALLOWED_HOSTS"), ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			hosts = append(hosts, h)
		}
	}
	return Policy{AllowedHosts: hosts}
}

// RepoRef is a parsed, validated repository location.
type RepoRef struct {
	Scheme string // https | ssh
	Host   string // lower-case, no port
	Port   string // "" when default
	Path   string // "/owner/repo(.git)"
	Raw    string
}

var (
	hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	pathRe = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{1,300}$`)
	portRe = regexp.MustCompile(`^[0-9]{1,5}$`)
)

// ErrBlockedHost is returned when a URL points at a forbidden network location.
var ErrBlockedHost = errors.New("repository host is not allowed")

// ParseRepoURL accepts only https://host/path or ssh://git@host[:port]/path.
// Credentials in the URL, query strings and fragments are rejected.
func ParseRepoURL(raw string) (*RepoRef, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 500 || strings.ContainsAny(raw, " \t\r\n\x00\\") || strings.HasPrefix(raw, "-") {
		return nil, errors.New("invalid repository URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid repository URL")
	}
	ref := &RepoRef{Scheme: u.Scheme, Raw: raw}
	switch u.Scheme {
	case "https":
		if u.User != nil {
			return nil, errors.New("credentials in the repository URL are not allowed")
		}
	case "ssh":
		if u.User == nil || u.User.Username() != "git" {
			return nil, errors.New("ssh repository URLs must be ssh://git@host/path")
		}
		if _, hasPw := u.User.Password(); hasPw {
			return nil, errors.New("credentials in the repository URL are not allowed")
		}
	default:
		return nil, errors.New("repository URL must be https:// or ssh://git@host")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid repository URL")
	}
	ref.Host = strings.ToLower(u.Hostname())
	ref.Port = u.Port()
	if ref.Port != "" && !portRe.MatchString(ref.Port) {
		return nil, errors.New("invalid repository port")
	}
	if ip := net.ParseIP(ref.Host); ip == nil && (!hostRe.MatchString(ref.Host) || strings.Contains(ref.Host, "..")) {
		return nil, errors.New("invalid repository host")
	}
	if !pathRe.MatchString(u.Path) || strings.Contains(u.Path, "..") || strings.Contains(u.Path, "//") {
		return nil, errors.New("invalid repository path")
	}
	ref.Path = u.Path
	return ref, nil
}

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, c := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "169.254.0.0/16",
		"64:ff9b::/96", "100::/64", "2001:db8::/32", "fec0::/10",
	} {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}()

// IsBlockedIP reports whether ip must never be contacted (private, loopback,
// link-local incl. cloud metadata, CGNAT, multicast, unspecified, reserved).
func IsBlockedIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() || addr.IsUnspecified() || addr.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (p Policy) lookup(ctx context.Context, host string) ([]net.IP, error) {
	if p.Lookup != nil {
		return p.Lookup(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

func (p Policy) hostAllowed(host string) bool {
	if len(p.AllowedHosts) == 0 {
		return true
	}
	for _, h := range p.AllowedHosts {
		if h == host {
			return true
		}
	}
	return false
}

// Resolve validates the host (allow-list + every resolved IP must be public)
// and returns the resolved addresses so callers can pin them.
func (p Policy) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	host = strings.ToLower(host)
	if !p.hostAllowed(host) {
		return nil, fmt.Errorf("%w: host not in CAPSULE_GIT_ALLOWED_HOSTS", ErrBlockedHost)
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return nil, fmt.Errorf("%w: private or reserved address", ErrBlockedHost)
		}
		return []net.IP{ip}, nil
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := p.lookup(rctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("repository host does not resolve")
	}
	for _, ip := range ips {
		if IsBlockedIP(ip) {
			return nil, fmt.Errorf("%w: resolves to a private or reserved address", ErrBlockedHost)
		}
	}
	return ips, nil
}

// ValidateRepoURL parses and checks raw against the policy.
func (p Policy) ValidateRepoURL(ctx context.Context, raw string) (*RepoRef, []net.IP, error) {
	ref, err := ParseRepoURL(raw)
	if err != nil {
		return nil, nil, err
	}
	ips, err := p.Resolve(ctx, ref.Host)
	if err != nil {
		return nil, nil, err
	}
	return ref, ips, nil
}

// NewHTTPClient returns an HTTP client for provider APIs that refuses
// private/reserved destinations (checked again at dial time, which defeats DNS
// rebinding) and re-validates every redirect (https only, same policy).
func (p Policy) NewHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || IsBlockedIP(ip) {
				return ErrBlockedHost
			}
			return nil
		},
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          4,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return p.CheckRedirectURL(req.Context(), req.URL)
		},
	}
}

// CheckRedirectURL validates a redirect target against the policy.
func (p Policy) CheckRedirectURL(ctx context.Context, u *url.URL) error {
	if u.Scheme != "https" || u.User != nil {
		return fmt.Errorf("%w: redirect to non-https or credentialed URL", ErrBlockedHost)
	}
	_, err := p.Resolve(ctx, u.Hostname())
	return err
}
