package data

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Route mirrors the Route schema of docs/gateway/API.openapi.yaml. Project is the project slug that the capsule/1
// header carries; the OpenAPI Route does not list it yet (it is optional here: routes without it are reachable by name
// but not through the tunnel).
type Route struct {
	ID          string  `json:"id"`
	ServiceID   string  `json:"service_id"`
	ProjectID   *string `json:"project_id"`
	OrgID       string  `json:"org_id"`
	Project     string  `json:"project,omitempty"`
	ProjectSlug string  `json:"project_slug,omitempty"` // accepted as an alias of Project
	Service     string  `json:"service"`
	Host        string  `json:"host"`
	Transport   string  `json:"transport"`
	Protocol    string  `json:"protocol"`
	DestHost    string  `json:"dest_host"`
	DestPort    int     `json:"dest_port"`
	Mode        string  `json:"mode"`
	Rev         int64   `json:"rev"`
}

// Lease mirrors LeaseView (random-port fallback; consumed by a later package).
type Lease struct {
	Port      int     `json:"port"`
	ServiceID string  `json:"service_id"`
	ProjectID *string `json:"project_id"`
	OrgID     string  `json:"org_id"`
}

// Snapshot is the response of GET /internal/gateway/routes.
type Snapshot struct {
	Rev    int64   `json:"rev"`
	Routes []Route `json:"routes"`
	Leases []Lease `json:"leases"`
}

// Credential types accepted by /internal/gateway/authorize. The OpenAPI enum is [cap, cgt, cgc, none]; the
// capsule/1 header also has cgs_ tokens (PROTOCOL.md section 11), sent as "cgs".
const (
	CredCap  = "cap"
	CredCgt  = "cgt"
	CredCgc  = "cgc"
	CredCgs  = "cgs"
	CredNone = "none"
)

// Access kinds of AuthorizeRequest.
const (
	AccessSNI        = "sni_name"
	AccessCapsuleURI = "capsule_uri"
	AccessRandomPort = "random_port"
)

// AuthorizeRequest mirrors AuthorizeRequest of the OpenAPI contract.
type AuthorizeRequest struct {
	RouteID        string `json:"route_id"`
	SrcIP          string `json:"src_ip"`
	CredentialType string `json:"credential_type"`
	Credential     string `json:"credential,omitempty"`
	Access         string `json:"access,omitempty"`
}

// AuthorizeResponse mirrors AuthorizeResponse of the OpenAPI contract.
type AuthorizeResponse struct {
	Allow           bool   `json:"allow"`
	PrincipalID     string `json:"principal_id"`
	DenyReason      string `json:"deny_reason"` // unauthorized | ip_denied | quota | unavailable (internal use only)
	MaxConns        int    `json:"max_conns"`
	MaxConnsPerIP   int    `json:"max_conns_per_ip"`
	IdleTimeoutSecs int    `json:"idle_timeout_seconds"`
	CacheTTLSeconds int    `json:"cache_ttl_seconds"`
}

// Control plane errors.
var (
	ErrControlUnauthorized = errors.New("control plane rejected the gateway secret")
	ErrControlRateLimited  = errors.New("control plane rate limited the gateway")
	ErrControlUnavailable  = errors.New("control plane unavailable")
)

// ControlPlane is the data plane's view of the Capsule backend (implemented over HTTP by HTTPControl; faked in tests;
// G3 implements the server side).
type ControlPlane interface {
	// Routes long-polls the route table. It returns (nil, nil) when nothing changed since `since` (HTTP 304).
	Routes(ctx context.Context, since int64, wait time.Duration) (*Snapshot, error)
	// Authorize asks whether the principal may connect to the route from the source IP.
	Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResponse, error)
}

// HTTPControl talks to the backend over HTTP with the shared secret header. The secret is never logged.
type HTTPControl struct {
	BaseURL string // e.g. http://backend:8080 (the /internal/gateway/... paths are appended)
	secret  string
	Client  *http.Client
}

// NewHTTPControl builds the client. Redirects are not followed so the secret never leaves the configured origin.
func NewHTTPControl(baseURL, secret string) (*HTTPControl, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid control plane URL")
	}
	tr := &http.Transport{
		Proxy:               nil,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &HTTPControl{
		BaseURL: strings.TrimRight(baseURL, "/"),
		secret:  secret,
		Client: &http.Client{
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (h *HTTPControl) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.BaseURL+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Gateway-Secret", h.secret)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		// the error text of net/http includes the URL only, never headers
		return nil, fmt.Errorf("%w: %v", ErrControlUnavailable, err)
	}
	return resp, nil
}

func mapStatus(resp *http.Response) error {
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ErrControlUnauthorized
	case resp.StatusCode == http.StatusTooManyRequests:
		return ErrControlRateLimited
	case resp.StatusCode >= 500:
		return fmt.Errorf("%w: status %d", ErrControlUnavailable, resp.StatusCode)
	case resp.StatusCode >= 400:
		return fmt.Errorf("control plane status %d", resp.StatusCode)
	}
	return nil
}

// Routes implements ControlPlane.
func (h *HTTPControl) Routes(ctx context.Context, since int64, wait time.Duration) (*Snapshot, error) {
	q := url.Values{}
	q.Set("since", strconv.FormatInt(since, 10))
	q.Set("wait", strconv.Itoa(int(wait/time.Second)))
	resp, err := h.do(ctx, http.MethodGet, "/internal/gateway/routes?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil, nil
	}
	if err := mapStatus(resp); err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&s); err != nil {
		return nil, fmt.Errorf("%w: bad routes body", ErrControlUnavailable)
	}
	return &s, nil
}

// Authorize implements ControlPlane.
func (h *HTTPControl) Authorize(ctx context.Context, req AuthorizeRequest) (*AuthorizeResponse, error) {
	b, _ := json.Marshal(req)
	resp, err := h.do(ctx, http.MethodPost, "/internal/gateway/authorize", b)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := mapStatus(resp); err != nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil, err
	}
	var out AuthorizeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: bad authorize body", ErrControlUnavailable)
	}
	return &out, nil
}
