package gitcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxResponseBytes = 8 << 20 // hard cap on any upstream body read into memory

// Service implements Core on top of the Forgejo REST API v1.
type Service struct {
	cfg   Config
	http  *http.Client
	cache Cache
	brk   *breaker
	sem   chan struct{}
	log   Logger
	web   *WebSession // nil without CAPSULE_GIT_BOT_PASSWORD

	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
	jit   func(n int64) int64
}

// Logger is the tiny logging contract (slog.Logger satisfies it).
type Logger interface {
	Warn(msg string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Warn(string, ...any) {}

// New builds the service. cache and log may be nil.
func New(cfg Config, cache Cache, log Logger) *Service {
	cfg = cfg.withDefaults()
	if log == nil {
		log = nopLogger{}
	}
	s := &Service{
		cfg:   cfg,
		cache: cache,
		log:   log,
		http: &http.Client{Timeout: cfg.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		sem:   make(chan struct{}, cfg.MaxConcurrent),
		now:   time.Now,
		sleep: sleepCtx,
		jit:   rand.Int63n,
	}
	s.brk = newBreaker(cfg.BreakerFailures, cfg.BreakerOpenFor, func() time.Time { return s.now() })
	s.web = newWebSession(s, cfg)
	return s
}

var _ Core = (*Service)(nil)

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Enabled reports whether URL and token are configured.
func (s *Service) Enabled() bool { return s.cfg.Enabled() }

// req describes one upstream call. op is a path TEMPLATE used in errors (no ids/secrets).
type req struct {
	method string
	path   string // already escaped, starts with "/", no query
	op     string
	query  url.Values
	body   any
	accept string // default application/json
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func idempotent(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodPut || m == http.MethodDelete
}

// do performs the call with breaker, concurrency limit, timeout, retries and error mapping.
func (s *Service) do(ctx context.Context, rq req, out any) (*resp, error) {
	op := rq.method + " " + rq.op
	if !s.cfg.Enabled() {
		return nil, &Error{Code: CodeNotReady, Message: "git integration is not configured", Op: op}
	}
	var payload []byte
	if rq.body != nil {
		b, err := json.Marshal(rq.body)
		if err != nil {
			return nil, &Error{Code: CodeInvalid, Message: "request body cannot be encoded", Op: op}
		}
		payload = b
	}
	// Non-idempotent calls are retried only when Forgejo says it did not process them (423).
	attempts := s.cfg.MaxAttempts
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			d := s.cfg.BackoffBase << (i - 1)
			if d > s.cfg.BackoffMax {
				d = s.cfg.BackoffMax
			}
			d = d/2 + time.Duration(s.jit(int64(d/2)+1)) // equal jitter
			if ra := retryAfter(last); ra > d {
				d = min(ra, s.cfg.BackoffMax)
			}
			if err := s.sleep(ctx, d); err != nil {
				return nil, s.ctxErr(err, op)
			}
		}
		if !s.brk.allow() {
			return nil, &Error{Code: CodeNotReady, Message: "git service temporarily unavailable (circuit open)", Op: op, Retry: true}
		}
		r, err := s.once(ctx, rq, payload, op)
		if err == nil {
			s.brk.record(true)
			if out != nil && len(r.body) > 0 {
				if jerr := json.Unmarshal(r.body, out); jerr != nil {
					return r, &Error{Code: CodeUpstream, Status: r.status, Message: "git service returned a malformed response", Op: op}
				}
			}
			return r, nil
		}
		e, _ := AsError(err)
		// Only upstream-side failures count against the breaker; 4xx do not.
		s.brk.record(e == nil || e.Code != CodeUpstream)
		last = err
		if e != nil && e.Status == 423 && attempts < 6 {
			// Forgejo's PR conflict check can take seconds: give locked calls a longer schedule.
			attempts = 6
		}
		if e == nil || !e.Retry || ctx.Err() != nil || (!idempotent(rq.method) && e.Status != 423) {
			return r, err
		}
	}
	return nil, last
}

func (s *Service) once(ctx context.Context, rq req, payload []byte, op string) (*resp, error) {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return nil, s.ctxErr(ctx.Err(), op)
	}
	u := s.cfg.URL + "/api/v1" + rq.path
	if len(rq.query) > 0 {
		u += "?" + rq.query.Encode()
	}
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	hr, err := http.NewRequestWithContext(ctx, rq.method, u, rd)
	if err != nil {
		return nil, &Error{Code: CodeInvalid, Message: "invalid request", Op: op}
	}
	accept := rq.accept
	if accept == "" {
		accept = "application/json"
	}
	hr.Header.Set("Accept", accept)
	hr.Header.Set("Authorization", "token "+s.cfg.Token)
	hr.Header.Set("User-Agent", "capsule-gitcore")
	if actor := ActorFrom(ctx); actor != "" {
		hr.Header.Set("Sudo", actor)
	}
	if payload != nil {
		hr.Header.Set("Content-Type", "application/json")
	}
	res, err := s.http.Do(hr)
	if err != nil {
		if ctx.Err() != nil {
			return nil, s.ctxErr(ctx.Err(), op)
		}
		// The transport error text can echo the URL; it is scrubbed and kept out of Message.
		return nil, &Error{Code: CodeUpstream, Message: "git service unreachable", Op: op, Retry: true, causeMsg: s.scrub(err.Error())}
	}
	defer res.Body.Close()
	data, rerr := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if rerr != nil {
		return nil, &Error{Code: CodeUpstream, Message: "git service connection broke while reading", Op: op, Retry: true}
	}
	if len(data) > maxResponseBytes {
		return nil, &Error{Code: CodeTooLarge, Status: res.StatusCode, Message: "git service response exceeds the size limit", Op: op}
	}
	r := &resp{status: res.StatusCode, header: res.Header, body: data}
	if res.StatusCode < 300 {
		return r, nil
	}
	return r, s.mapStatus(res.StatusCode, data, res.Header, op)
}

func (s *Service) ctxErr(err error, op string) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Code: CodeUpstream, Message: "git service timed out", Op: op, Retry: true, Cause: context.DeadlineExceeded}
	}
	return &Error{Code: CodeUpstream, Message: "request cancelled", Op: op, Cause: err}
}

// scrub removes the service token from text.
func (s *Service) scrub(t string) string {
	if s.cfg.Token != "" {
		t = strings.ReplaceAll(t, s.cfg.Token, "***")
	}
	return t
}

func (s *Service) mapStatus(status int, body []byte, h http.Header, op string) error {
	msg := strings.TrimSpace(string(body))
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &m) == nil && m.Message != "" {
		msg = m.Message
	}
	msg = s.scrub(msg)
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if msg == "" {
		msg = http.StatusText(status)
	}
	e := &Error{Status: status, Message: msg, Op: op}
	switch {
	case status == 404:
		e.Code = CodeNotFound
	case status == 403:
		e.Code = CodeForbidden
	case status == 423:
		// Locked: Forgejo is busy with this PR (conflict check, another merge) and did NOT apply the
		// request, so it is safe to retry even for POST. Observed on a real v15.0.11 right after
		// creating a PR ("Please try again later").
		e.Code, e.Retry = CodeConflict, true
	case status == 409 || status == 405: // 405: merge not allowed now (checks, approvals)
		e.Code = CodeConflict
	case status == 413:
		e.Code = CodeTooLarge
	case status == 400 || status == 422:
		e.Code = CodeUnprocessed
	case status == 429:
		e.Code, e.Retry = CodeUpstream, true
		if ra, err := strconv.Atoi(h.Get("Retry-After")); err == nil && ra > 0 {
			e.causeMsg = "retry-after:" + strconv.Itoa(ra)
		}
	case status == 401:
		// Our service token was rejected (operator problem, not the user's) OR Forgejo answered 401
		// "Permission denied" for an endpoint the token may not use (seen on push_mirrors, v15.0.11).
		e.Code, e.Message = CodeUpstream, "git service answered 401 (service credentials or endpoint permission): "+msg
	case status >= 500:
		e.Code, e.Retry = CodeUpstream, true
	default:
		e.Code = CodeUpstream
	}
	return e
}

func retryAfter(err error) time.Duration {
	if e, ok := AsError(err); ok && strings.HasPrefix(e.causeMsg, "retry-after:") {
		n, _ := strconv.Atoi(strings.TrimPrefix(e.causeMsg, "retry-after:"))
		return time.Duration(n) * time.Second
	}
	return 0
}

// ---- helpers ------------------------------------------------------------------

func esc(s string) string { return url.PathEscape(s) }

// escPath escapes each segment of a slash-separated path (file paths, branch names).
func escPath(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

func (r RepoRef) base() string { return "/repos/" + esc(r.Owner) + "/" + esc(r.Repo) }

func (r RepoRef) valid() error {
	bad := func(s string) bool { return s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\?#%") }
	if bad(r.Owner) || bad(r.Repo) {
		return &Error{Code: CodeInvalid, Message: "invalid repository reference"}
	}
	return nil
}

func invalid(format string, a ...any) error {
	return &Error{Code: CodeInvalid, Message: fmt.Sprintf(format, a...)}
}

func isHexSHA(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func parseTimePtr(s string) *time.Time {
	t := parseTime(s)
	if t.IsZero() {
		return nil
	}
	return &t
}
