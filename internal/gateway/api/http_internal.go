package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// SecretHeader carries the shared secret of /internal/gateway/*.
const SecretHeader = "X-Gateway-Secret"

// secretEqual compares in constant time and independently of the length (both sides are hashed first).
func secretEqual(got, want string) bool {
	a, b := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// MountInternal registers the endpoints of the data plane on the ROOT router: outside the user middleware and outside
// the custom-domain middleware (they skip /internal/ paths). They are closed unless CAPSULE_GW_SECRET is set,
// and refuse anything that came through the public load balancer.
func (s *Service) MountInternal(root chi.Router) {
	root.Get("/internal/gateway/routes", s.handleRoutes)
	root.Post("/internal/gateway/authorize", s.handleAuthorize)
	root.Get("/internal/gateway/keys", s.handleKeys)
}

// internalCaller reports whether the call may use the internal API, writing the refusal when not.
//   - came through the public ALB (it always adds X-Amzn-Trace-Id): 403
//   - no secret configured: 503 (closed by default, like /internal/git-auth)
//   - wrong or missing secret: 401; repeated failures from one address are blocked (429)
func (s *Service) internalCaller(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("X-Amzn-Trace-Id") != "" {
		writeErr(w, s.log, &Error{Status: http.StatusForbidden, Code: "forbidden", Message: "forbidden"})
		return false
	}
	if s.cfg.Secret == "" {
		writeErr(w, s.log, &Error{Status: http.StatusServiceUnavailable, Code: "internal", Message: "gateway control plane is not enabled"})
		return false
	}
	key := "secret|" + middleware.ClientIP(r)
	if blocked, wait := s.lim.Blocked(key); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		writeErr(w, s.log, &Error{Status: http.StatusTooManyRequests, Code: "rate_limited", Message: "too many attempts"})
		return false
	}
	if !secretEqual(r.Header.Get(SecretHeader), s.cfg.Secret) {
		s.lim.Fail(key)
		writeErr(w, s.log, &Error{Status: http.StatusUnauthorized, Code: "unauthorized", Message: "invalid credentials"})
		return false
	}
	return true
}

// GET /internal/gateway/routes?since=&wait=
func (s *Service) handleRoutes(w http.ResponseWriter, r *http.Request) {
	if !s.internalCaller(w, r) {
		return
	}
	since := int64(-1)
	if v := r.URL.Query().Get("since"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeErr(w, s.log, errBadRequest("since must be a non-negative integer"))
			return
		}
		since = n
	}
	wait := s.cfg.DefaultWait
	if v := r.URL.Query().Get("wait"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 60 {
			writeErr(w, s.log, errBadRequest("wait must be between 0 and 60 seconds"))
			return
		}
		wait = time.Duration(n) * time.Second
	}
	snap, changed, err := s.WaitRoutes(r.Context(), since, wait)
	if err != nil {
		writeErr(w, s.log, err)
		return
	}
	w.Header().Set("X-Gateway-Rev", strconv.FormatInt(snap.Rev, 10))
	if !changed {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// POST /internal/gateway/authorize
func (s *Service) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if !s.internalCaller(w, r) {
		return
	}
	var req AuthorizeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeErr(w, s.log, errBadRequest("invalid request body"))
		return
	}
	res, err := s.Authorize(r.Context(), req)
	if err != nil {
		if e, ok := asError(err); ok && e.Status == http.StatusTooManyRequests {
			if secs, ok := e.Details["retry_after_seconds"].(int); ok {
				w.Header().Set("Retry-After", strconv.Itoa(secs))
			}
		}
		writeErr(w, s.log, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// GET /internal/gateway/keys: public keys that verify cgc_ tokens (the data plane validates them without calling back).
func (s *Service) handleKeys(w http.ResponseWriter, r *http.Request) {
	if !s.internalCaller(w, r) {
		return
	}
	keys := []KeyInfo{}
	if s.signer != nil {
		keys = s.signer.Keys()
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}
