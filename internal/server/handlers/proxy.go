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
}

func NewProxyHandler(orgs domain.OrganizationRepository, projects domain.ProjectRepository) *ProxyHandler {
	return &ProxyHandler{orgs: orgs, projects: projects}
}

// Proxy routes /apps/{orgSlug}/{projectSlug}/* to the running container.
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

	// Container name is capsule-app-{first 12 chars of projectID without dashes}
	shortID := strings.ReplaceAll(project.ID.String(), "-", "")[:12]
	containerName := "capsule-app-" + shortID

	target, _ := url.Parse(fmt.Sprintf("http://%s:3000", containerName))

	// Strip /apps/{orgSlug}/{projectSlug} prefix
	stripPrefix := "/apps/" + orgSlug + "/" + projectSlug
	r.URL.Path = strings.TrimPrefix(r.URL.Path, stripPrefix)
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, fmt.Sprintf("app not running: %v", err), http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
}
