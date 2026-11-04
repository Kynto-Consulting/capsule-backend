package handlers

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/ingress"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// memDomains is an in-memory DomainRepository that counts lookups.
type memDomains struct {
	mu      sync.Mutex
	rows    map[string]*domain.Domain
	lookups int
	err     error
}

func (m *memDomains) Create(_ context.Context, d *domain.Domain) (*domain.Domain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows == nil {
		m.rows = map[string]*domain.Domain{}
	}
	c := *d
	c.ID = uuid.New()
	m.rows[d.DomainName] = &c
	return &c, nil
}
func (m *memDomains) GetByID(_ context.Context, id uuid.UUID) (*domain.Domain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.rows {
		if d.ID == id {
			c := *d
			return &c, nil
		}
	}
	return nil, domain.ErrNotFound
}
func (m *memDomains) GetByHostname(_ context.Context, h string) (*domain.Domain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lookups++
	if m.err != nil {
		return nil, m.err
	}
	// same filter as the SQL: status IN ('verified','active')
	if d, ok := m.rows[h]; ok && (d.Status == "verified" || d.Status == "active") {
		c := *d
		return &c, nil
	}
	return nil, domain.ErrNotFound
}
func (m *memDomains) ListByProject(context.Context, uuid.UUID) ([]*domain.Domain, error) {
	return nil, nil
}
func (m *memDomains) ListByOrg(context.Context, uuid.UUID) ([]*domain.Domain, error) { return nil, nil }
func (m *memDomains) UpdateStatus(_ context.Context, id uuid.UUID, status, rv string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.rows {
		if d.ID == id {
			d.Status, d.RecordValue = status, rv
			return nil
		}
	}
	return domain.ErrNotFound
}
func (m *memDomains) UpdateSSL(_ context.Context, id uuid.UUID, ssl bool, tok string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range m.rows {
		if d.ID == id {
			d.SSLEnabled, d.VerificationToken = ssl, tok
			return nil
		}
	}
	return domain.ErrNotFound
}
func (m *memDomains) Delete(context.Context, uuid.UUID) error { return nil }

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func askRig(t *testing.T) (*TLSAskHandler, *memDomains, http.Handler) {
	t.Helper()
	proj := uuid.New()
	repo := &memDomains{}
	for name, st := range map[string]string{
		"activo.cliente.com": "active", "verificado.cliente.com": "verified",
		"pendiente.cliente.com": "pending_dns", "fallido.cliente.com": "failed", "pendiente-viejo.cliente.com": "pending",
	} {
		_, _ = repo.Create(context.Background(), &domain.Domain{DomainName: name, Status: st, ProjectID: &proj})
	}
	_, _ = repo.Create(context.Background(), &domain.Domain{DomainName: "huerfano.cliente.com", Status: "active"}) // org-level
	own := ingress.Config{Host: "ingress.apps.example.com", AppsDomain: "apps.example.com", OwnHosts: []string{"app.example.com", "api.example.com"}}.OwnSet()
	h := NewTLSAskHandler(repo, own, quiet())
	// production stack order: CaptureRemoteAddr, chi RealIP (trusts client headers), then the route on the root router
	r := chi.NewRouter()
	r.Use(middleware.CaptureRemoteAddr)
	r.Use(chiMiddleware.RealIP)
	r.Use(middleware.InternalEdgeGuard)
	h.Mount(r)
	return h, repo, r
}

func askDo(h http.Handler, domainParam string, hdr map[string]string, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/internal/tls/ask?domain="+url.QueryEscape(domainParam), nil)
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestTLSAsk_200OnlyForVerifiedActiveAndOwnNames(t *testing.T) {
	_, _, h := askRig(t)
	allowed := []string{"activo.cliente.com", "ACTIVO.cliente.com", "activo.cliente.com.", "verificado.cliente.com",
		"app.example.com", "api.example.com", "apps.example.com", "ingress.apps.example.com"}
	for _, d := range allowed {
		if r := askDo(h, d, nil, "172.18.0.5:4000"); r.Code != 200 || r.Body.Len() != 0 {
			t.Errorf("%s: %d body=%q, want 200 empty", d, r.Code, r.Body.String())
		}
	}
	denied := []string{"pendiente.cliente.com", "fallido.cliente.com", "pendiente-viejo.cliente.com", "huerfano.cliente.com",
		"desconocido.cliente.com", "", ".", "..", "a..b.com", "activo.cliente.com:443", "activo.cliente.com/x", "*.cliente.com",
		"x.apps.example.com", "10.0.0.1", "ñandú.pe", "activo.cliente.com\x00"}
	var first *httptest.ResponseRecorder
	for _, d := range denied {
		r := askDo(h, d, nil, "172.18.0.5:4000")
		if r.Code != 404 || r.Body.Len() != 0 {
			t.Errorf("%q: %d body=%q, want 404 empty", d, r.Code, r.Body.String())
		}
		if first == nil {
			first = r
		} else if r.Header().Get("Content-Type") != first.Header().Get("Content-Type") || r.Header().Get("Cache-Control") != first.Header().Get("Cache-Control") {
			t.Errorf("%q: denial headers differ between reasons", d)
		}
	}
	// missing parameter and other methods
	req := httptest.NewRequest("GET", "/internal/tls/ask", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Errorf("no parameter: %d", rec.Code)
	}
}

// The endpoint answers only from the "domain" parameter and the database: no client header changes the answer.
func TestTLSAsk_DoesNotDependOnClientHeaders(t *testing.T) {
	_, _, h := askRig(t)
	hostile := map[string]string{
		"Host":               "activo.cliente.com",
		"X-Forwarded-Host":   "activo.cliente.com",
		"X-Forwarded-For":    "203.0.113.50, 10.0.0.2",
		"X-Real-IP":          "203.0.113.50",
		"X-Forwarded-Proto":  "https",
		"X-Amzn-Trace-Id":    "Root=1-abc",
		"Forwarded":          "for=203.0.113.50;host=activo.cliente.com",
		"Authorization":      "Bearer admin",
		"X-Capsule-Git-Auth": "x",
	}
	for _, d := range []string{"activo.cliente.com", "desconocido.cliente.com", "pendiente.cliente.com", "app.example.com"} {
		base := askDo(h, d, nil, "172.18.0.5:4000").Code
		for k, v := range hostile {
			// a Host header of its own is set on the request line, not as a header map entry
			req := httptest.NewRequest("GET", "/internal/tls/ask?domain="+url.QueryEscape(d), nil)
			req.RemoteAddr = "172.18.0.5:4000"
			if k == "Host" {
				req.Host = v
			} else {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			// the ask route is exempt from InternalEdgeGuard, so even a public X-Forwarded-For does not change the answer
			h.ServeHTTP(rec, req)
			if rec.Code != base {
				t.Errorf("%s with %s: %d, want %d", d, k, rec.Code, base)
			}
		}
	}
}

func TestTLSAsk_CacheAvoidsRepeatedLookups(t *testing.T) {
	ask, repo, h := askRig(t)
	now := time.Unix(1_700_000_000, 0)
	ask.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		askDo(h, "activo.cliente.com", nil, "172.18.0.5:1")
		askDo(h, "desconocido.cliente.com", nil, "172.18.0.5:1")
		askDo(h, "app.example.com", nil, "172.18.0.5:1") // own names never touch the database
	}
	if repo.lookups != 2 {
		t.Fatalf("lookups = %d, want 2 (one per host, then cached)", repo.lookups)
	}
	now = now.Add(11 * time.Second) // negative entries are short-lived
	askDo(h, "desconocido.cliente.com", nil, "172.18.0.5:1")
	askDo(h, "activo.cliente.com", nil, "172.18.0.5:1")
	if repo.lookups != 3 {
		t.Fatalf("after negTTL: lookups = %d, want 3", repo.lookups)
	}
	now = now.Add(31 * time.Second)
	askDo(h, "activo.cliente.com", nil, "172.18.0.5:1")
	if repo.lookups != 4 {
		t.Fatalf("after posTTL: lookups = %d, want 4", repo.lookups)
	}
	// a newly activated domain is picked up after the negative TTL (at most ~10 s)
	proj := uuid.New()
	_, _ = repo.Create(context.Background(), &domain.Domain{DomainName: "nuevo.cliente.com", Status: "pending_dns", ProjectID: &proj})
	if askDo(h, "nuevo.cliente.com", nil, "172.18.0.5:1").Code != 404 {
		t.Fatal("pending must be denied")
	}
	repo.mu.Lock()
	repo.rows["nuevo.cliente.com"].Status = "active"
	repo.mu.Unlock()
	now = now.Add(11 * time.Second)
	if askDo(h, "nuevo.cliente.com", nil, "172.18.0.5:1").Code != 200 {
		t.Fatal("active must be allowed once the negative entry expired")
	}
}

func TestTLSAsk_DatabaseErrorsDenyAndAreNotCached(t *testing.T) {
	_, repo, h := askRig(t)
	repo.err = errors.New("connection refused")
	if r := askDo(h, "activo.cliente.com", nil, "172.18.0.5:1"); r.Code != 404 {
		t.Fatalf("db error: %d", r.Code)
	}
	repo.mu.Lock()
	repo.err = nil
	repo.mu.Unlock()
	if r := askDo(h, "activo.cliente.com", nil, "172.18.0.5:1"); r.Code != 200 {
		t.Fatalf("after recovery: %d (errors must not be cached)", r.Code)
	}
}

func TestTLSAsk_RateLimitPerSourceAddressIgnoresHeaders(t *testing.T) {
	ask, _, h := askRig(t)
	ask.rps, ask.burst = 1, 5
	deny := 0
	for i := 0; i < 20; i++ {
		// the attacker rotates X-Forwarded-For / X-Real-IP: the limiter keys on the socket address only
		hdr := map[string]string{"X-Forwarded-For": "10.1.1." + string(rune('0'+i%10)), "X-Real-IP": "10.2.2.2"}
		if askDo(h, "activo.cliente.com", hdr, "172.18.0.9:5000").Code == 404 {
			deny++
		}
	}
	if deny < 10 {
		t.Fatalf("only %d of 20 burst requests were limited", deny)
	}
	// another source address is unaffected
	if r := askDo(h, "activo.cliente.com", nil, "172.18.0.10:5000"); r.Code != 200 {
		t.Fatalf("other address: %d", r.Code)
	}
}

func TestTLSAsk_OnlyGET(t *testing.T) {
	_, _, h := askRig(t)
	req := httptest.NewRequest("POST", "/internal/tls/ask?domain=activo.cliente.com", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == 200 {
		t.Fatal("POST must not authorise")
	}
}
