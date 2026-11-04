package handlers

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// TLSAskHandler is GET /internal/tls/ask?domain=<host>, the target of Caddy's
// on_demand_tls { ask ... }. Caddy calls it before every certificate issuance;
// 200 authorises the issuance, any other status denies it.
//
// Contract:
//   - 200 with an empty body ONLY when <host> is a verified (status verified|active)
//     custom domain attached to a project, or one of Capsule's own names
//     (app, api, apps, ingress host: ingress.Config.OwnSet);
//   - 404 with an empty body in EVERY other case (unknown host, malformed host,
//     missing parameter, database error, rate limit): the response never says why.
//
// Security model (documented requirement, see docs/ingress-without-alb.md):
//   - The endpoint has no secret: Caddy reaches it over the internal Docker
//     network. It must NEVER be reachable from the internet: Caddy has to block
//     /internal/* on every public site. Even if it were reachable it only reveals
//     whether a name is allowed to get a certificate, and it is read-only.
//   - The answer depends exclusively on the "domain" query parameter and the
//     database. No client-supplied header (Host, X-Forwarded-*, X-Real-IP, ...)
//     influences it; only the original socket address feeds the rate limiter.
//   - Lookups use the unique index on domains.domain_name, are cached briefly in
//     memory and limited per source address, so nobody can use it to trigger
//     a flood of issuances or database queries.
type TLSAskHandler struct {
	domains domain.DomainRepository
	own     map[string]bool
	logger  *slog.Logger
	now     func() time.Time

	posTTL, negTTL time.Duration
	maxEntries     int

	mu    sync.Mutex
	cache map[string]askEntry

	limMu    sync.Mutex
	limiters map[string]*rate.Limiter
	rps      rate.Limit
	burst    int
}

type askEntry struct {
	ok      bool
	expires time.Time
}

// NewTLSAskHandler builds the handler. own is the set of Capsule's own host names
// (lower-case, no trailing dot).
func NewTLSAskHandler(domains domain.DomainRepository, own map[string]bool, logger *slog.Logger) *TLSAskHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &TLSAskHandler{
		domains: domains, own: own, logger: logger, now: time.Now,
		posTTL: 30 * time.Second, negTTL: 10 * time.Second, maxEntries: 10000,
		cache:    map[string]askEntry{},
		limiters: map[string]*rate.Limiter{},
		rps:      20, burst: 40,
	}
}

// Mount registers the route on the ROOT router (outside the user and the custom-domain middleware,
// like /internal/git-auth).
func (h *TLSAskHandler) Mount(root chi.Router) {
	root.Get("/internal/tls/ask", h.ServeHTTP)
}

func (h *TLSAskHandler) deny(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
}

func (h *TLSAskHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.allow(sourceIP(r)) {
		h.logger.Warn("tls ask: rate limited", "ip", sourceIP(r))
		h.deny(w)
		return
	}
	host, ok := normalizeAskHost(r.URL.Query().Get("domain"))
	if !ok {
		h.deny(w)
		return
	}
	if h.own[host] || h.lookup(r.Context(), host) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		return
	}
	h.deny(w)
}

func (h *TLSAskHandler) lookup(ctx context.Context, host string) bool {
	now := h.now()
	h.mu.Lock()
	if e, ok := h.cache[host]; ok && now.Before(e.expires) {
		h.mu.Unlock()
		return e.ok
	}
	h.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	d, err := h.domains.GetByHostname(ctx, host)
	allowed := false
	switch {
	case err == nil:
		allowed = d != nil && d.ProjectID != nil && (d.Status == "active" || d.Status == "verified")
	case errors.Is(err, domain.ErrNotFound):
	default:
		h.logger.Warn("tls ask: lookup failed", "error", err)
		return false // errors are not cached
	}
	ttl := h.negTTL
	if allowed {
		ttl = h.posTTL
	}
	h.mu.Lock()
	if len(h.cache) >= h.maxEntries {
		h.cache = map[string]askEntry{} // bound the memory; entries are cheap to rebuild
	}
	h.cache[host] = askEntry{ok: allowed, expires: now.Add(ttl)}
	h.mu.Unlock()
	return allowed
}

func (h *TLSAskHandler) allow(ip string) bool {
	h.limMu.Lock()
	defer h.limMu.Unlock()
	if len(h.limiters) >= 4096 {
		h.limiters = map[string]*rate.Limiter{}
	}
	l, ok := h.limiters[ip]
	if !ok {
		l = rate.NewLimiter(h.rps, h.burst)
		h.limiters[ip] = l
	}
	return l.Allow()
}

// sourceIP is the socket peer, never a header.
func sourceIP(r *http.Request) string {
	addr := middleware.RemoteAddr(r)
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// normalizeAskHost lower-cases the host and accepts only plausible DNS names.
func normalizeAskHost(s string) (string, bool) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || len(s) > 253 {
		return "", false
	}
	for _, ch := range s {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '.') {
			return "", false
		}
	}
	if strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
		return "", false
	}
	return s, true
}
