package handlers

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/kynto/capsule/backend/internal/gittokens"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// GitAuthInternalHandler is GET /internal/git-auth, the target of Caddy's forward_auth
// (deploy/forgejo/Caddyfile, INTEGRATION.md "Borde de acceso").
//
// Contract with Caddy:
//   - request: the Git client's Authorization header, plus X-Forwarded-Method / X-Forwarded-Uri
//     (set by forward_auth) and X-Forwarded-For (client IP);
//   - 200 without X-WEBAUTH-USER: not a cgt_ credential, Forgejo authenticates it itself;
//   - 200 with X-WEBAUTH-USER: valid cgt_ token inside its scope; Forgejo trusts the header;
//   - 401 (WWW-Authenticate), 403, 429 (Retry-After), 503: returned to the Git client as is.
//
// The endpoint answers nothing useful to anyone but the edge: it demands the shared secret
// Caddy adds (header X-Capsule-Git-Auth, CAPSULE_GIT_AUTH_SECRET) and refuses requests that went
// through the public load balancer (it always adds X-Amzn-Trace-Id). Without a configured secret
// it is closed, except with CAPSULE_GIT_AUTH_ALLOW_UNSECURED=1 for local development.
type GitAuthInternalHandler struct {
	svc    *gittokens.Service
	logger *slog.Logger
}

const gitAuthSecretHeader = "X-Capsule-Git-Auth"

// internalCaller reports whether the call may use the endpoint.
func (h *GitAuthInternalHandler) internalCaller(r *http.Request) (ok bool, status int) {
	if r.Header.Get("X-Amzn-Trace-Id") != "" {
		return false, http.StatusForbidden // came through the public ALB
	}
	cfg := h.svc.Config()
	if cfg.AuthSecret == "" {
		if cfg.AllowUnsecured {
			return true, 0
		}
		return false, http.StatusServiceUnavailable
	}
	if !gittokens.SecretEqual(r.Header.Get(gitAuthSecretHeader), cfg.AuthSecret) {
		return false, http.StatusForbidden
	}
	return true, 0
}

func (h *GitAuthInternalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// Whatever the caller sent in X-WEBAUTH-USER is never read nor echoed: only forward_auth's
	// response header, set below, reaches Forgejo.
	w.Header().Del("X-WEBAUTH-USER")
	if ok, status := h.internalCaller(r); !ok {
		http.Error(w, http.StatusText(status), status)
		return
	}
	user, pass, hasBasic := r.BasicAuth()
	d := h.svc.Authenticate(r.Context(), gittokens.AuthRequest{
		HasBasic: hasBasic,
		User:     user,
		Password: pass,
		Method:   r.Header.Get("X-Forwarded-Method"),
		URI:      r.Header.Get("X-Forwarded-Uri"),
		IP:       middleware.ClientIP(r),
	})
	switch d.Outcome {
	case gittokens.OutcomePass:
		w.WriteHeader(http.StatusOK)
	case gittokens.OutcomeAllow:
		w.Header().Set("X-WEBAUTH-USER", d.Login)
		w.WriteHeader(http.StatusOK)
	case gittokens.OutcomeUnauthorized:
		h.logDenied(r, d)
		w.Header().Set("WWW-Authenticate", `Basic realm="Git Capsule", charset="UTF-8"`)
		http.Error(w, "invalid or expired token", http.StatusUnauthorized)
	case gittokens.OutcomeForbidden:
		h.logDenied(r, d)
		http.Error(w, "forbidden", http.StatusForbidden)
	case gittokens.OutcomeLimited:
		secs := int(d.RetryAfter.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	default:
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}
}

// logDenied logs the verdict with the token id and reason, never the credential.
func (h *GitAuthInternalHandler) logDenied(r *http.Request, d gittokens.Decision) {
	if h.logger == nil {
		return
	}
	h.logger.Info("git auth denied", "reason", d.Reason, "token_id", d.TokenID.String(), "ip", middleware.ClientIP(r))
}
