package handlers

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/kynto/capsule/backend/internal/domain"
)

type ProxyHandler struct {
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
	domains  domain.DomainRepository
}

func NewProxyHandler(orgs domain.OrganizationRepository, projects domain.ProjectRepository, domains domain.DomainRepository) *ProxyHandler {
	return &ProxyHandler{orgs: orgs, projects: projects, domains: domains}
}

// ProxyBySlug handles /_proxy/{subdomain}/* — called by Next.js rewrites for *.apps.tumi-ai.com.
// Subdomain patterns:
//   - {slug}           → HTTP proxy to deployed container
//   - {slug}-storage   → S3 storage proxy info
//   - {slug}-db        → Database connection info
func (h *ProxyHandler) ProxyBySlug(w http.ResponseWriter, r *http.Request) {
	subdomain := chi.URLParam(r, "subdomain")

	// Parse resource type from subdomain suffix
	projectSlug, resourceType := parseSubdomain(subdomain)

	project, err := h.projects.GetBySlugGlobal(r.Context(), projectSlug)
	if err == domain.ErrNotFound {
		http.Error(w, fmt.Sprintf("project %q not found", projectSlug), http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	switch resourceType {
	case "app":
		if project.DeployType == "static" {
			staticBucket := "capsule-static-348973061281" // TODO: make configurable
			websiteURL := fmt.Sprintf("http://%s.s3-website-us-east-1.amazonaws.com/%s%s",
				staticBucket, project.ID.String()+"/",
				strings.TrimPrefix(r.URL.Path, "/_proxy/"+subdomain))
			http.Redirect(w, r, websiteURL, http.StatusFound)
			return
		}
		h.proxyToContainer(w, r, project, subdomain)
	case "storage":
		h.handleStorageInfo(w, r, project)
	case "db":
		h.handleDBInfo(w, r, project)
	default:
		http.Error(w, "unknown resource type", http.StatusNotFound)
	}
}

// ProxyByHost handles requests arriving with a custom domain Host header.
// It looks up the verified domain record and either redirects or proxies to the container.
func (h *ProxyHandler) ProxyByHost(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	// Strip port if present
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}

	d, err := h.domains.GetByHostname(r.Context(), host)
	if err == domain.ErrNotFound {
		http.Error(w, "domain not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Handle redirect domains
	if strings.HasPrefix(d.DNSProvider, "redirect:") {
		target := strings.TrimPrefix(d.DNSProvider, "redirect:")
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return
	}

	project, err := h.projects.GetByID(r.Context(), d.ProjectID)
	if err == domain.ErrNotFound {
		http.Error(w, "project not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if project.DeployType == "static" {
		staticBucket := "capsule-static-348973061281" // TODO: make configurable
		path := r.URL.Path
		if path == "" {
			path = "/"
		}
		websiteURL := fmt.Sprintf("http://%s.s3-website-us-east-1.amazonaws.com/%s%s",
			staticBucket, project.ID.String(), path)
		http.Redirect(w, r, websiteURL, http.StatusFound)
		return
	}
	h.proxyToContainer(w, r, project, "")
}

// Proxy handles /apps/{orgSlug}/{projectSlug}/* — legacy path-based routing (kept for backward compat).
func (h *ProxyHandler) Proxy(w http.ResponseWriter, r *http.Request) {
	orgSlug := chi.URLParam(r, "orgSlug")
	projectSlug := chi.URLParam(r, "projectSlug")

	org, err := h.orgs.GetBySlug(r.Context(), orgSlug)
	if err != nil {
		http.Error(w, "org not found", http.StatusNotFound)
		return
	}

	project, err := h.projects.GetBySlug(r.Context(), org.ID, projectSlug)
	if err != nil {
		http.Error(w, "project not found", http.StatusNotFound)
		return
	}

	stripPrefix := "/apps/" + orgSlug + "/" + projectSlug
	r.URL.Path = strings.TrimPrefix(r.URL.Path, stripPrefix)
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}

	if project.DeployType == "static" {
		staticBucket := "capsule-static-348973061281" // TODO: make configurable
		websiteURL := fmt.Sprintf("http://%s.s3-website-us-east-1.amazonaws.com/%s%s",
			staticBucket, project.ID.String(), r.URL.Path)
		http.Redirect(w, r, websiteURL, http.StatusFound)
		return
	}
	h.proxyToContainer(w, r, project, projectSlug)
}

// ── internal helpers ─────────────────────────────────────────────────────────

func parseSubdomain(subdomain string) (projectSlug, resourceType string) {
	for _, suffix := range []string{"-storage", "-db", "-mail"} {
		if strings.HasSuffix(subdomain, suffix) {
			return strings.TrimSuffix(subdomain, suffix), strings.TrimPrefix(suffix, "-")
		}
	}
	return subdomain, "app"
}

func containerName(project *domain.Project) string {
	shortID := strings.ReplaceAll(project.ID.String(), "-", "")[:12]
	return "capsule-app-" + shortID
}

func (h *ProxyHandler) proxyToContainer(w http.ResponseWriter, r *http.Request, project *domain.Project, subdomain string) {
	name := containerName(project)
	target, _ := url.Parse(fmt.Sprintf("http://%s:3000", name))

	// Strip /_proxy/{subdomain} prefix when coming via Next.js rewrite
	prefix := "/_proxy/" + subdomain
	if strings.HasPrefix(r.URL.Path, prefix) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, fmt.Sprintf("app not running — deploy first: %v", err), http.StatusBadGateway)
	}
	// Forward original host so the app knows its public URL
	r.Header.Set("X-Forwarded-Host", r.Host)
	proxy.ServeHTTP(w, r)
}

func (h *ProxyHandler) handleStorageInfo(w http.ResponseWriter, r *http.Request, project *domain.Project) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"project_id":%q,"message":"S3 storage proxy — coming soon"}`, project.ID)
}

func (h *ProxyHandler) handleDBInfo(w http.ResponseWriter, r *http.Request, project *domain.Project) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"project_id":%q,"message":"Database info endpoint — coming soon"}`, project.ID)
}
