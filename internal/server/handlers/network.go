package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/netaccess"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// allowlistTTL bounds how long a project's allowlist is served from memory.
// A change made on this instance is visible immediately (cache invalidated);
// other instances pick it up within the TTL.
const allowlistTTL = 15 * time.Second

type allowlistEntry struct {
	cidrs   []string
	expires time.Time
}

// AllowlistCache caches per-project IP allowlists in front of the database.
type AllowlistCache struct {
	repo domain.ProjectNetworkRepository
	ttl  time.Duration
	now  func() time.Time
	mu   sync.RWMutex
	m    map[uuid.UUID]allowlistEntry
}

func NewAllowlistCache(repo domain.ProjectNetworkRepository, ttl time.Duration) *AllowlistCache {
	if ttl <= 0 {
		ttl = allowlistTTL
	}
	return &AllowlistCache{repo: repo, ttl: ttl, now: time.Now, m: map[uuid.UUID]allowlistEntry{}}
}

// Get returns the project's allowlist. On a lookup error it serves a stale
// entry when it has one; otherwise it returns the error (callers fail closed).
func (c *AllowlistCache) Get(ctx context.Context, projectID uuid.UUID) ([]string, error) {
	c.mu.RLock()
	e, ok := c.m[projectID]
	c.mu.RUnlock()
	if ok && c.now().Before(e.expires) {
		return e.cidrs, nil
	}
	cidrs, err := c.repo.GetIPAllowlist(ctx, projectID)
	if err != nil {
		if ok {
			return e.cidrs, nil
		}
		return nil, err
	}
	c.mu.Lock()
	if len(c.m) > 10000 { // crude bound; entries are tiny and re-fetched on demand
		c.m = map[uuid.UUID]allowlistEntry{}
	}
	c.m[projectID] = allowlistEntry{cidrs: cidrs, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
	return cidrs, nil
}

// Invalidate drops the cached entry (called after a local update).
func (c *AllowlistCache) Invalidate(projectID uuid.UUID) {
	c.mu.Lock()
	delete(c.m, projectID)
	c.mu.Unlock()
}

// Allowed reports whether ip may reach the project. An empty list means public.
func (c *AllowlistCache) Allowed(ctx context.Context, projectID uuid.UUID, ip string) (bool, error) {
	cidrs, err := c.Get(ctx, projectID)
	if err != nil {
		return false, err
	}
	if len(cidrs) == 0 {
		return true, nil
	}
	return netaccess.ContainsIP(cidrs, ip), nil
}

// NetworkHandler serves /network/my-ip and the per-project network settings.
type NetworkHandler struct {
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
	repo     domain.ProjectNetworkRepository
	cache    *AllowlistCache
}

func NewNetworkHandler(orgs domain.OrganizationRepository, projects domain.ProjectRepository, repo domain.ProjectNetworkRepository, cache *AllowlistCache) *NetworkHandler {
	return &NetworkHandler{orgs: orgs, projects: projects, repo: repo, cache: cache}
}

// GET /network/my-ip  ->  {"ip":"x.x.x.x"}
func (h *NetworkHandler) MyIP(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"ip": middleware.ClientIP(r)})
}

func (h *NetworkHandler) load(w http.ResponseWriter, r *http.Request, write bool) (uuid.UUID, bool) {
	user := middleware.GetUser(r.Context())
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return uuid.Nil, false
	}
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return uuid.Nil, false
	}
	role, err := h.orgs.GetMemberRole(r.Context(), orgID, user.ID)
	if err != nil {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
		return uuid.Nil, false
	}
	if write && !canWriteOrg(role) {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "your role cannot change network settings")
		return uuid.Nil, false
	}
	project, err := h.projects.GetByID(r.Context(), projectID)
	if err == domain.ErrNotFound || (err == nil && project.OrgID != orgID) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "project not found")
		return uuid.Nil, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get project")
		return uuid.Nil, false
	}
	return projectID, true
}

// GET /orgs/{orgID}/projects/{projectID}/network  ->  {"ip_allowlist":["1.2.3.0/24"]}
func (h *NetworkHandler) Get(w http.ResponseWriter, r *http.Request) {
	projectID, ok := h.load(w, r, false)
	if !ok {
		return
	}
	cidrs, err := h.repo.GetIPAllowlist(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get network settings")
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ip_allowlist": cidrs})
}

// PUT /orgs/{orgID}/projects/{projectID}/network  {"ip_allowlist":["1.2.3.4/32"]}  (empty list = public)
func (h *NetworkHandler) Put(w http.ResponseWriter, r *http.Request) {
	projectID, ok := h.load(w, r, true)
	if !ok {
		return
	}
	var body struct {
		IPAllowlist []string `json:"ip_allowlist"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	cidrs, err := normalizeAllowlist(body.IPAllowlist)
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_CIDR", err.Error())
		return
	}
	if err := h.repo.SetIPAllowlist(r.Context(), projectID, cidrs); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save network settings")
		return
	}
	if h.cache != nil {
		h.cache.Invalidate(projectID)
	}
	respondJSON(w, http.StatusOK, map[string]any{"ip_allowlist": cidrs})
}

// normalizeAllowlist validates, canonicalises and de-duplicates an allowlist.
// 0.0.0.0/0 is rejected: an empty list already means "public".
func normalizeAllowlist(in []string) ([]string, error) {
	if len(in) > netaccess.MaxAllowlistEntries {
		return nil, &allowlistError{"at most 50 entries are allowed"}
	}
	out := []string{}
	seen := map[string]bool{}
	for _, raw := range in {
		c, err := netaccess.NormalizeCIDR(raw, false)
		if err != nil {
			if strings.Contains(err.Error(), netaccess.ErrPublicCIDR.Error()) {
				return nil, &allowlistError{"0.0.0.0/0 is not a valid allowlist entry; use an empty list to make the app public"}
			}
			return nil, err
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

type allowlistError struct{ msg string }

func (e *allowlistError) Error() string { return e.msg }
