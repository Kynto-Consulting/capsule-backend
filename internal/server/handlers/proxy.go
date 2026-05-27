package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

type ProxyHandler struct {
	orgs        domain.OrganizationRepository
	projects    domain.ProjectRepository
	domains     domain.DomainRepository
	deployments domain.DeploymentRepository
	aws         *awsclient.Clients
}

func NewProxyHandler(orgs domain.OrganizationRepository, projects domain.ProjectRepository, domains domain.DomainRepository, deployments domain.DeploymentRepository, aws *awsclient.Clients) *ProxyHandler {
	return &ProxyHandler{orgs: orgs, projects: projects, domains: domains, deployments: deployments, aws: aws}
}

// staticBucketName returns the S3 static bucket name, configurable via CAPSULE_STATIC_BUCKET.
func staticBucketName() string {
	if b := os.Getenv("CAPSULE_STATIC_BUCKET"); b != "" {
		return b
	}
	return "capsule-static-348973061281"
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
			subPath := strings.TrimPrefix(r.URL.Path, "/_proxy/"+subdomain)
			if subPath == "" || subPath == "/" {
				subPath = "/index.html"
			}
			websiteURL := fmt.Sprintf("http://%s.s3-website-us-east-1.amazonaws.com/%s%s",
				staticBucketName(), project.ID.String(), subPath)
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
		path := r.URL.Path
		if path == "" {
			path = "/"
		}
		websiteURL := fmt.Sprintf("http://%s.s3-website-us-east-1.amazonaws.com/%s%s",
			staticBucketName(), project.ID.String(), path)
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
		websiteURL := fmt.Sprintf("http://%s.s3-website-us-east-1.amazonaws.com/%s%s",
			staticBucketName(), project.ID.String(), r.URL.Path)
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
	// Lambda: invoke via AWS SDK (IAM / instance role — no Function URL needed)
	if project.DeployType == "lambda" {
		h.proxyToLambda(w, r, project, subdomain)
		return
	}

	// Docker container proxy
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

// lambdaHTTPEvent is the Lambda HTTP API Gateway V2 payload format.
// Serverless frameworks (Next.js via Lambda Web Adapter, Express, etc.) all understand this.
type lambdaHTTPEvent struct {
	Version               string            `json:"version"`
	RouteKey              string            `json:"routeKey"`
	RawPath               string            `json:"rawPath"`
	RawQueryString        string            `json:"rawQueryString"`
	Headers               map[string]string `json:"headers"`
	QueryStringParameters map[string]string `json:"queryStringParameters,omitempty"`
	RequestContext        struct {
		AccountID string `json:"accountId"`
		APIID     string `json:"apiId"`
		HTTP      struct {
			Method    string `json:"method"`
			Path      string `json:"path"`
			Protocol  string `json:"protocol"`
			SourceIP  string `json:"sourceIp"`
			UserAgent string `json:"userAgent"`
		} `json:"http"`
		RequestID string `json:"requestId"`
		RouteKey  string `json:"routeKey"`
		Stage     string `json:"stage"`
		Time      string `json:"time"`
	} `json:"requestContext"`
	Body            string `json:"body,omitempty"`
	IsBase64Encoded bool   `json:"isBase64Encoded"`
}

type lambdaHTTPResponse struct {
	StatusCode        int                 `json:"statusCode"`
	Headers           map[string]string   `json:"headers"`
	MultiValueHeaders map[string][]string `json:"multiValueHeaders,omitempty"`
	Body              string              `json:"body,omitempty"`
	IsBase64Encoded   bool                `json:"isBase64Encoded"`
}

func (h *ProxyHandler) proxyToLambda(w http.ResponseWriter, r *http.Request, project *domain.Project, subdomain string) {
	if h.aws == nil || h.aws.Lambda == nil {
		http.Error(w, "Lambda client not available", http.StatusServiceUnavailable)
		return
	}

	// Derive function name from project ID (same as deploy worker)
	shortID := strings.ReplaceAll(project.ID.String(), "-", "")[:12]
	functionName := "capsule-" + shortID

	// Strip proxy prefix from path
	reqPath := r.URL.Path
	if subdomain != "" {
		prefix := "/_proxy/" + subdomain
		if strings.HasPrefix(reqPath, prefix) {
			reqPath = strings.TrimPrefix(reqPath, prefix)
		}
	}
	if reqPath == "" {
		reqPath = "/"
	}

	// Build headers map (lowercase keys, single values)
	headers := make(map[string]string)
	for k, vals := range r.Header {
		headers[strings.ToLower(k)] = strings.Join(vals, ",")
	}
	headers["x-forwarded-for"] = r.RemoteAddr
	headers["x-forwarded-host"] = r.Host
	headers["x-forwarded-proto"] = "https"

	// Build query string parameters
	qp := make(map[string]string)
	for k, vals := range r.URL.Query() {
		qp[k] = strings.Join(vals, ",")
	}

	// Read body
	var bodyStr string
	var isBase64 bool
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 6*1024*1024)) // 6MB limit
		if err == nil && len(bodyBytes) > 0 {
			bodyStr = base64.StdEncoding.EncodeToString(bodyBytes)
			isBase64 = true
		}
	}

	event := lambdaHTTPEvent{
		Version:               "2.0",
		RouteKey:              "$default",
		RawPath:               reqPath,
		RawQueryString:        r.URL.RawQuery,
		Headers:               headers,
		QueryStringParameters: qp,
		Body:                  bodyStr,
		IsBase64Encoded:       isBase64,
	}
	event.RequestContext.HTTP.Method = r.Method
	event.RequestContext.HTTP.Path = reqPath
	event.RequestContext.HTTP.Protocol = "HTTP/1.1"
	event.RequestContext.HTTP.SourceIP = r.RemoteAddr
	event.RequestContext.HTTP.UserAgent = r.UserAgent()
	event.RequestContext.RouteKey = "$default"
	event.RequestContext.Stage = "$default"

	payload, err := json.Marshal(event)
	if err != nil {
		http.Error(w, "failed to build lambda event", http.StatusInternalServerError)
		return
	}

	// Invoke Lambda function via SDK (uses instance role / IAM credentials)
	result, err := h.aws.Lambda.Invoke(r.Context(), &lambda.InvokeInput{
		FunctionName: aws.String(functionName),
		Payload:      payload,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("lambda invocation failed: %v", err), http.StatusBadGateway)
		return
	}

	// Handle Lambda errors
	if result.FunctionError != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write(result.Payload)
		return
	}

	// Parse response
	var resp lambdaHTTPResponse
	if err := json.Unmarshal(result.Payload, &resp); err != nil {
		// Raw response (non-HTTP format function) — return payload as-is
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(result.Payload)
		return
	}

	// Write headers
	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}
	for k, vals := range resp.MultiValueHeaders {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}

	statusCode := resp.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	w.WriteHeader(statusCode)

	// Write body
	if resp.Body != "" {
		if resp.IsBase64Encoded {
			decoded, err := base64.StdEncoding.DecodeString(resp.Body)
			if err == nil {
				w.Write(decoded)
			} else {
				w.Write([]byte(resp.Body))
			}
		} else {
			w.Write([]byte(resp.Body))
		}
	}
}

func (h *ProxyHandler) handleStorageInfo(w http.ResponseWriter, r *http.Request, project *domain.Project) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"project_id":%q,"message":"S3 storage proxy — coming soon"}`, project.ID)
}

func (h *ProxyHandler) handleDBInfo(w http.ResponseWriter, r *http.Request, project *domain.Project) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"project_id":%q,"message":"Database info endpoint — coming soon"}`, project.ID)
}
