package connaudit

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Endpoint is a parsed connection target. Cred is true when the source carried
// credentials; they are never kept.
type Endpoint struct {
	Scheme string
	Host   string
	Port   int
	Cred   bool
}

// String is the sanitised form: scheme://[***@]host[:port], no path or query.
func (e Endpoint) String() string {
	h := e.Host
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		h = "[" + h + "]"
	}
	if e.Port > 0 {
		h += ":" + strconv.Itoa(e.Port)
	}
	if e.Scheme == "" {
		return h
	}
	cred := ""
	if e.Cred {
		cred = "***@"
	}
	return e.Scheme + "://" + cred + h
}

var urlRe = regexp.MustCompile("(?i)(jdbc:[a-z0-9]+|postgres(?:ql)?|mysql|mariadb|rediss?|mongodb(?:\\+srv)?|amqps?|https?|tcp|ssl|wss?|kafka|nats|memcached|sqlserver)://([^\\s'\"`<>(){},;\\\\|^]+)")

var defaultPorts = map[string]int{
	"postgres": 5432, "postgresql": 5432, "mysql": 3306, "mariadb": 3306, "redis": 6379, "rediss": 6379,
	"mongodb": 27017, "amqp": 5672, "amqps": 5671, "http": 80, "https": 443, "ws": 80, "wss": 443,
}

// ExtractURLs finds every URL-shaped endpoint in text.
func ExtractURLs(text string) []Endpoint {
	var out []Endpoint
	for _, m := range urlRe.FindAllStringSubmatch(text, -1) {
		if ep, ok := parseAuthority(strings.ToLower(m[1]), m[2]); ok {
			out = append(out, ep)
		}
	}
	return out
}

// parseAuthority parses "user:pass@host:port/path?q" (the part after "://").
func parseAuthority(scheme, rest string) (Endpoint, bool) {
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	ep := Endpoint{Scheme: scheme}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		ep.Cred = true
		rest = rest[i+1:]
	}
	host, port, ok := splitHostPort(rest)
	if !ok || host == "" {
		return ep, false
	}
	ep.Host, ep.Port = host, port
	if ep.Port == 0 {
		base := strings.TrimPrefix(ep.Scheme, "jdbc:")
		ep.Port = defaultPorts[strings.SplitN(base, "+", 2)[0]]
	}
	return ep, true
}

var hostRe = regexp.MustCompile(`^[a-zA-Z0-9*_.\-]+$`)

// splitHostPort handles host, host:port, [v6], [v6]:port and bare IPv6.
func splitHostPort(s string) (string, int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, false
	}
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", 0, false
		}
		h := s[1:end]
		if _, err := netip.ParseAddr(strings.SplitN(h, "%", 2)[0]); err != nil {
			return "", 0, false
		}
		port := 0
		if tail := s[end+1:]; tail != "" {
			if !strings.HasPrefix(tail, ":") {
				return "", 0, false
			}
			p, err := strconv.Atoi(tail[1:])
			if err != nil || p < 0 || p > 65535 {
				return "", 0, false
			}
			port = p
		}
		return h, port, true
	}
	if a, err := netip.ParseAddr(s); err == nil { // bare IPv6 (or IPv4)
		return a.String(), 0, true
	}
	port := 0
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		if strings.Count(s, ":") != 1 {
			return "", 0, false
		}
		p, err := strconv.Atoi(s[i+1:])
		if err != nil || p < 0 || p > 65535 {
			return "", 0, false
		}
		port, s = p, s[:i]
	}
	if !hostRe.MatchString(s) {
		return "", 0, false
	}
	return s, port, true
}

// ParseHostPort parses a bare "host[:port]" value (an *_HOST or *_ADDR variable).
func ParseHostPort(v string) (Endpoint, bool) {
	v = strings.Trim(strings.TrimSpace(v), `"'`)
	if strings.Contains(v, "://") {
		return Endpoint{}, false
	}
	h, p, ok := splitHostPort(v)
	if !ok {
		return Endpoint{}, false
	}
	return Endpoint{Host: h, Port: p}, true
}

var hostSuffixes = []string{"_HOSTNAME", "_HOST", "_ADDRESS", "_ADDR", "_ENDPOINT", "_SERVER", "HOST"}

// HostKeyPrefix reports whether key names the host of some dependency and returns
// its prefix ("DB" for DB_HOST, "PG" for PGHOST). Bare HOST/HOSTNAME (a listen
// address) and LISTEN/BIND/APP-style prefixes are excluded.
func HostKeyPrefix(key string) (string, bool) {
	k := strings.ToUpper(key)
	for _, suf := range hostSuffixes {
		if strings.HasSuffix(k, suf) {
			p := strings.TrimRight(strings.TrimSuffix(k, suf), "_")
			if p == "" {
				return "", false
			}
			switch p {
			case "LISTEN", "BIND", "APP", "WEB", "PUBLIC", "NEXT_PUBLIC", "SERVER", "HTTP":
				return "", false
			}
			return p, true
		}
	}
	return "", false
}

// urlKey: variables that conventionally hold a connection URL or DSN, whose value
// may also be a bare host:port.
func urlKey(key string) bool {
	k := strings.ToUpper(key)
	for _, s := range []string{"_URL", "_URI", "_DSN", "_BROKER", "_BROKERS", "_CONNECTION", "_CONNECTION_STRING"} {
		if strings.HasSuffix(k, s) {
			return true
		}
	}
	return false
}
