package gitcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// =============================================================================================
// WebSession: the ONLY place that talks to Forgejo's internal, undocumented WEB routes.
//
// WHY: Forgejo v15.0.11's REST API has no endpoint for the jobs of a run, the logs of a job,
// cancelling or re-running a run, nor for run artifacts (all answer 404). Its own web UI does all
// of that through session-authenticated routes (cookie, NOT token/Basic: those answer 404). So
// this file logs in as the service account "capsule-bot" with its password (CAPSULE_GIT_BOT_PASSWORD)
// and calls the same routes the UI does.
//
// FRAGILITY, READ BEFORE TOUCHING: these routes are not an API. Their paths and JSON shapes can
// change in any Forgejo release without notice. Therefore:
//   - everything that depends on them lives in this file;
//   - it only runs against Forgejo versions listed in Config.WebVersions (default: the one it was
//     verified against, TestedForgejoVersion). Another version degrades to NOT_SUPPORTED with the
//     reason, instead of guessing;
//   - every response is shape-checked; a changed shape is an UPSTREAM error naming the route (the
//     `-tags=forgejo` smoke test, itest/web_test.go, fails loudly on the same condition).
//
// Verified against Forgejo 15.0.11 (source routers/web/repo/actions/view.go + live runs):
//   POST /{o}/{r}/actions/runs/{runIndex}/jobs/{jobIndex}   body {"logCursors":[{step,cursor,expanded}]}
//        -> {state:{run:{jobs:[{id,name,status,canRerun,duration}],status,canCancel,canRerun,done},
//                   currentJob:{steps:[{summary,duration,status}],allAttempts:[{number}]}},
//            logs:{stepsLog:[{step,cursor,lines:[{index,message,timestamp}]}]}}
//        (runIndex is the repository-local run NUMBER = index_in_repo, not the run id)
//   POST /{o}/{r}/actions/runs/{runIndex}/cancel            -> 200 {}
//   POST /{o}/{r}/actions/runs/{runIndex}/rerun             -> 200 {"redirect":...} (SAME run, new attempt)
//   POST /{o}/{r}/actions/runs/{runIndex}/jobs/{jobIndex}/rerun
//   GET  /{o}/{r}/actions/runs/{runIndex}/artifacts         -> {"artifacts":[{name,size,status}]}
//   GET  /{o}/{r}/actions/runs/{runID}/artifacts/{name}     -> zip (NOTE: this one takes the run ID)
//   Authentication: POST /user/login (user_name, password). 15.0.11 has no CSRF token (it uses
//   Go's cross-origin protection: requests without Origin/Sec-Fetch-Site are accepted).
// =============================================================================================

// TestedForgejoVersion is the Forgejo release the web routes above were verified against.
const TestedForgejoVersion = "15.0.11"

const (
	webLoginFailTTL   = 30 * time.Second // do not hammer /user/login with a rejected password
	webVersionOKTTL   = 10 * time.Minute
	webMaxJobs        = 512 // bounds of the in-memory caches
	webMaxLogJobs     = 64
	webMaxLogBytesJob = 8 << 20
	webMaxArtifact    = 512 << 20
)

// WebSession is a cached, self-renewing web login of the service account.
type WebSession struct {
	svc      *Service
	login    string
	password string
	versions []string
	hc       atomic.Pointer[http.Client]
	timeout  time.Duration

	mu        sync.Mutex // serializes logins and guards the fields below
	loggedIn  bool
	gen       uint64
	failUntil time.Time
	failErr   *Error
	verOK     bool
	verAt     time.Time
	version   string

	cmu    sync.Mutex // guards the caches below
	runIdx map[int64]int64
	jobLoc map[int64]webJobLoc
	logs   map[int64]*webLogBuf
}

type webJobLoc struct {
	RunID, RunIndex int64
	JobIndex        int
	Repo            RepoRef
}

func newWebSession(s *Service, cfg Config) *WebSession {
	if cfg.BotPassword == "" {
		return nil
	}
	jar, _ := cookiejar.New(nil)
	login := cfg.BotLogin
	if login == "" {
		login = "capsule-bot"
	}
	vs := cfg.WebVersions
	if len(vs) == 0 {
		vs = []string{TestedForgejoVersion}
	}
	w := &WebSession{svc: s, login: login, password: cfg.BotPassword, versions: vs, timeout: cfg.Timeout,
		runIdx: map[int64]int64{}, jobLoc: map[int64]webJobLoc{}, logs: map[int64]*webLogBuf{}}
	w.hc.Store(w.newClient(jar))
	return w
}

func (w *WebSession) newClient(jar http.CookieJar) *http.Client {
	return &http.Client{Timeout: w.timeout, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// WebEnabled reports whether the web-session features are configured (a bot password is set).
// It does not prove the bot credentials or the Forgejo version are acceptable: that is checked on
// first use and reported as NOT_SUPPORTED with the reason.
func (s *Service) WebEnabled() bool { return s.web != nil }

func (s *Service) webOff(op string, r RepoRef) error {
	where := s.cfg.URL
	if r.Owner != "" && r.Repo != "" {
		where += "/" + r.Owner + "/" + r.Repo + "/actions"
	}
	return unsupported(op, "this needs the Forgejo web interface session of the service account (CAPSULE_GIT_BOT_PASSWORD is not configured); use Forgejo directly: "+where)
}

// webReason builds a NOT_SUPPORTED error that keeps the Forgejo link.
func (w *WebSession) webReason(op string, r RepoRef, why string) *Error {
	where := w.svc.cfg.URL
	if r.Owner != "" && r.Repo != "" {
		where += "/" + r.Owner + "/" + r.Repo + "/actions"
	}
	return &Error{Code: CodeUnsupported, Message: why + "; use Forgejo directly: " + where, Op: op}
}

// versionAllowed: entries are exact versions ("15.0.11"), prefixes ("15.0.*") or "*" (any).
func versionAllowed(v string, allowed []string) bool {
	for _, a := range allowed {
		a = strings.TrimSpace(a)
		switch {
		case a == "*":
			return true
		case strings.HasSuffix(a, ".*") && strings.HasPrefix(v, strings.TrimSuffix(a, "*")):
			return true
		case a == v:
			return true
		}
	}
	return false
}

func cleanVersion(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "+-"); i >= 0 {
		v = v[:i]
	}
	return v
}

// checkVersion asks the (token) API for the Forgejo version and gates the web routes on it.
func (w *WebSession) checkVersion(ctx context.Context, op string, r RepoRef) error {
	// caller holds w.mu
	if w.verOK && w.svc.now().Sub(w.verAt) < webVersionOKTTL {
		return nil
	}
	var v struct {
		Version string `json:"version"`
	}
	if _, err := w.svc.do(ctx, req{method: http.MethodGet, path: "/version", op: "/version"}, &v); err != nil {
		return err
	}
	cv := cleanVersion(v.Version)
	if !versionAllowed(cv, w.versions) {
		w.verOK = false
		return w.webReason(op, r, fmt.Sprintf("Forgejo %q is not a version the web-session routes were verified against (%s); set CAPSULE_GIT_WEB_VERSIONS to allow it after re-running the forgejo smoke test", cv, strings.Join(w.versions, ", ")))
	}
	w.verOK, w.verAt, w.version = true, w.svc.now(), cv
	return nil
}

type webResp struct {
	status int
	header http.Header
	body   []byte
}

var csrfRe = regexp.MustCompile(`name="_csrf"[^>]*?(?:value|content)="([^"]+)"|(?:value|content)="([^"]+)"[^>]*?name="_csrf"`)

// rawReq performs one request with the cookie jar (never logs headers, cookies or bodies).
func (w *WebSession) rawReq(ctx context.Context, method, path string, body []byte, ctype, accept string, limit int64) (*webResp, error) {
	select {
	case w.svc.sem <- struct{}{}:
		defer func() { <-w.svc.sem }()
	case <-ctx.Done():
		return nil, w.svc.ctxErr(ctx.Err(), method+" web")
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	hr, err := http.NewRequestWithContext(ctx, method, w.svc.cfg.URL+path, rd)
	if err != nil {
		return nil, &Error{Code: CodeInvalid, Message: "invalid request", Op: method + " web"}
	}
	hr.Header.Set("User-Agent", "capsule-gitcore")
	if accept != "" {
		hr.Header.Set("Accept", accept)
	}
	if ctype != "" {
		hr.Header.Set("Content-Type", ctype)
	}
	res, err := w.hc.Load().Do(hr)
	if err != nil {
		if ctx.Err() != nil {
			return nil, w.svc.ctxErr(ctx.Err(), method+" web")
		}
		return nil, &Error{Code: CodeUpstream, Message: "git service unreachable", Op: method + " web", Retry: true}
	}
	defer res.Body.Close()
	data, rerr := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if rerr != nil {
		return nil, &Error{Code: CodeUpstream, Message: "git service connection broke while reading", Op: method + " web", Retry: true}
	}
	if int64(len(data)) > limit {
		return nil, &Error{Code: CodeTooLarge, Status: res.StatusCode, Message: "git service response exceeds the size limit", Op: method + " web"}
	}
	return &webResp{status: res.StatusCode, header: res.Header, body: data}, nil
}

func isLoginRedirect(r *webResp) bool {
	if r.status >= 300 && r.status < 400 {
		l := r.header.Get("Location")
		return strings.Contains(l, "/user/login")
	}
	return false
}

// doLogin authenticates; caller holds w.mu. Failures are cached for webLoginFailTTL.
func (w *WebSession) doLogin(ctx context.Context, op string, r RepoRef) error {
	if w.svc.now().Before(w.failUntil) && w.failErr != nil {
		e := *w.failErr
		return &e
	}
	fail := func(why string) error {
		e := w.webReason(op, r, why)
		w.failErr, w.failUntil = e, w.svc.now().Add(webLoginFailTTL)
		return e
	}
	// A fresh jar: a stale session cookie must not survive a relogin.
	jar, _ := cookiejar.New(nil)
	w.hc.Store(w.newClient(jar))
	pg, err := w.rawReq(ctx, http.MethodGet, "/user/login", nil, "", "text/html", 1<<20)
	if err != nil {
		return err
	}
	form := url.Values{"user_name": {w.login}, "password": {w.password}}
	if m := csrfRe.FindSubmatch(pg.body); m != nil { // older Forgejo versions; 15.0.11 has none
		tok := string(m[1])
		if tok == "" {
			tok = string(m[2])
		}
		form.Set("_csrf", tok)
	}
	res, err := w.rawReq(ctx, http.MethodPost, "/user/login", []byte(form.Encode()), "application/x-www-form-urlencoded", "text/html", 1<<20)
	if err != nil {
		return err
	}
	loc := res.header.Get("Location")
	switch {
	case res.status >= 300 && res.status < 400 && strings.Contains(loc, "two_factor"), strings.Contains(loc, "webauthn"):
		return fail("the service account has two-factor authentication enabled; the web session cannot log in (disable 2FA on the bot account)")
	case res.status >= 300 && res.status < 400 && strings.Contains(loc, "change_password"):
		return fail("the service account must change its password before it can log in (create it with --must-change-password=false)")
	case res.status >= 300 && res.status < 400 && !strings.Contains(loc, "/user/login"):
		w.loggedIn = true
		w.gen++
		w.failErr = nil
		return nil
	case res.status >= 500:
		return &Error{Code: CodeUpstream, Status: res.status, Message: "git service failed the web login", Op: op, Retry: true}
	default:
		return fail("the web login of the service account was rejected (check CAPSULE_GIT_BOT_LOGIN / CAPSULE_GIT_BOT_PASSWORD)")
	}
}

func (w *WebSession) ensure(ctx context.Context, op string, r RepoRef) (uint64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkVersion(ctx, op, r); err != nil {
		return 0, err
	}
	if !w.loggedIn {
		if err := w.doLogin(ctx, op, r); err != nil {
			return 0, err
		}
	}
	return w.gen, nil
}

// invalidate drops the session if nobody renewed it since generation gen.
func (w *WebSession) invalidate(gen uint64) {
	w.mu.Lock()
	if w.gen == gen {
		w.loggedIn = false
	}
	w.mu.Unlock()
}

// sessionAlive asks a login-only page whether the session still works (used to tell an expired
// session from a genuine 404, because Forgejo answers 404 to anonymous users on private repos).
func (w *WebSession) sessionAlive(ctx context.Context) bool {
	res, err := w.rawReq(ctx, http.MethodGet, "/user/settings", nil, "", "text/html", 4<<20)
	return err == nil && res.status == http.StatusOK
}

// do runs one web request with login, expiry detection (one re-login + retry) and, for
// idempotent reads, transient-failure retries. The result is checked by status: 2xx is returned,
// anything else becomes a *Error (404 NotFound, 403 Forbidden, 400 Conflict with Forgejo's own
// message, 5xx Upstream).
func (w *WebSession) do(ctx context.Context, op string, r RepoRef, method, path string, body []byte, ctype, accept string, limit int64, readOnly bool) (*webResp, error) {
	relogged := false
	attempts := 1
	if readOnly {
		attempts = w.svc.cfg.MaxAttempts
	}
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			d := w.svc.cfg.BackoffBase << (i - 1)
			if d > w.svc.cfg.BackoffMax {
				d = w.svc.cfg.BackoffMax
			}
			if err := w.svc.sleep(ctx, d); err != nil {
				return nil, w.svc.ctxErr(err, op)
			}
		}
		if !w.svc.brk.allow() {
			return nil, &Error{Code: CodeNotReady, Message: "git service temporarily unavailable (circuit open)", Op: op, Retry: true}
		}
		gen, err := w.ensure(ctx, op, r)
		if err != nil {
			return nil, err
		}
		res, err := w.rawReq(ctx, method, path, body, ctype, accept, limit)
		if err != nil {
			e, _ := AsError(err)
			w.svc.brk.record(e == nil || e.Code != CodeUpstream)
			last = err
			if e != nil && e.Retry && readOnly {
				continue
			}
			return nil, err
		}
		w.svc.brk.record(res.status < 500)
		expired := isLoginRedirect(res) || res.status == 401 ||
			(res.status == 200 && strings.Contains(res.header.Get("Content-Type"), "text/html") && accept == "application/json")
		if !expired && (res.status == 404 || res.status == 403) && !relogged {
			expired = !w.sessionAlive(ctx)
		}
		if expired {
			if relogged {
				return nil, &Error{Code: CodeUpstream, Status: res.status, Message: "the web session of the service account was rejected right after logging in", Op: op}
			}
			relogged = true
			w.invalidate(gen)
			i-- // the renewal does not use up a retry
			continue
		}
		if res.status < 300 {
			return res, nil
		}
		if res.status >= 500 {
			last = &Error{Code: CodeUpstream, Status: res.status, Message: "git service failed the request", Op: op, Retry: true}
			if readOnly {
				continue
			}
			return nil, last
		}
		return nil, webStatusErr(res, op)
	}
	if last == nil {
		last = &Error{Code: CodeUpstream, Message: "git service unavailable", Op: op, Retry: true}
	}
	return nil, last
}

func webStatusErr(res *webResp, op string) error {
	msg := ""
	var m struct {
		E string `json:"errorMessage"`
		M string `json:"message"`
	}
	if json.Unmarshal(res.body, &m) == nil {
		msg = m.E + m.M
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	e := &Error{Status: res.status, Message: msg, Op: op}
	switch res.status {
	case 404:
		e.Code = CodeNotFound
		if e.Message == "" {
			e.Message = "not found"
		}
	case 403:
		e.Code = CodeForbidden
		if e.Message == "" {
			e.Message = "the service account is not allowed to do this (it must be a site admin or have write access to the repository's Actions)"
		}
	case 400, 409, 422:
		e.Code = CodeConflict
		if e.Message == "" {
			e.Message = "Forgejo refused the action"
		}
	default:
		e.Code = CodeUpstream
		if e.Message == "" {
			e.Message = "unexpected answer from the git service"
		}
	}
	return e
}

func shapeErr(op, what string) error {
	return &Error{Code: CodeUpstream, Message: "unexpected Forgejo web response shape (" + what + "): the internal web route changed; verified only on Forgejo " + TestedForgejoVersion, Op: op}
}

// ---------------------------------------------------------------------------------------------
// Run/job addressing
// ---------------------------------------------------------------------------------------------

func (w *WebSession) runIndex(ctx context.Context, r RepoRef, runID int64) (int64, error) {
	w.cmu.Lock()
	idx, ok := w.runIdx[runID]
	w.cmu.Unlock()
	if ok {
		return idx, nil
	}
	run, err := w.svc.GetRun(ctx, r, runID)
	if err != nil {
		return 0, err
	}
	if run.Index < 1 {
		return 0, shapeErr("GET /repos/{o}/{r}/actions/runs/{id}", "index_in_repo missing")
	}
	w.cmu.Lock()
	if len(w.runIdx) > webMaxJobs {
		w.runIdx = map[int64]int64{}
	}
	w.runIdx[runID] = run.Index
	w.cmu.Unlock()
	return run.Index, nil
}

func (w *WebSession) jobPath(r RepoRef, runIndex int64, rest string) string {
	return "/" + esc(r.Owner) + "/" + esc(r.Repo) + "/actions/runs/" + i64(runIndex) + rest
}

type webJob struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	CanRerun bool   `json:"canRerun"`
	Duration string `json:"duration"`
}

type webStep struct {
	Summary  string `json:"summary"`
	Duration string `json:"duration"`
	Status   string `json:"status"`
}

type webLine struct {
	Index     int64   `json:"index"`
	Message   string  `json:"message"`
	Timestamp float64 `json:"timestamp"`
}

type webView struct {
	State *struct {
		Run *struct {
			Status    string    `json:"status"`
			CanCancel bool      `json:"canCancel"`
			CanRerun  bool      `json:"canRerun"`
			Done      bool      `json:"done"`
			Jobs      *[]webJob `json:"jobs"`
		} `json:"run"`
		CurrentJob *struct {
			Steps       *[]webStep `json:"steps"`
			AllAttempts *[]struct {
				Number int64 `json:"number"`
			} `json:"allAttempts"`
		} `json:"currentJob"`
	} `json:"state"`
	Logs *struct {
		StepsLog *[]struct {
			Step   int       `json:"step"`
			Cursor int64     `json:"cursor"`
			Lines  []webLine `json:"lines"`
		} `json:"stepsLog"`
	} `json:"logs"`
}

type webCursor struct {
	Step     int   `json:"step"`
	Cursor   int64 `json:"cursor"`
	Expanded bool  `json:"expanded"`
}

// jobRest is the path below the run: the plain job URL carries no steps or logs (attempt 0 finds no
// task), so those are read from the explicit attempt URL, which the UI uses too.
func jobRest(jobIndex int, attempt int64) string {
	p := "/jobs/" + itoa(jobIndex)
	if attempt > 0 {
		p += "/attempt/" + i64(attempt)
	}
	return p
}

const opView = "POST /{o}/{r}/actions/runs/{run}/jobs/{job}"

// view POSTs the UI's state endpoint for job jobIndex of run runIndex.
func (w *WebSession) view(ctx context.Context, r RepoRef, runIndex int64, jobIndex int, attempt int64, cur []webCursor) (*webView, error) {
	if cur == nil {
		cur = []webCursor{}
	}
	b, _ := json.Marshal(map[string]any{"logCursors": cur})
	res, err := w.do(ctx, opView, r, http.MethodPost, w.jobPath(r, runIndex, jobRest(jobIndex, attempt)), b, "application/json", "application/json", maxResponseBytes, true)
	if err != nil {
		return nil, err
	}
	var v webView
	if err := json.Unmarshal(res.body, &v); err != nil {
		return nil, shapeErr(opView, "not JSON")
	}
	if v.State == nil || v.State.Run == nil || v.State.Run.Jobs == nil || v.State.CurrentJob == nil || v.Logs == nil || v.Logs.StepsLog == nil {
		return nil, shapeErr(opView, "state.run.jobs / state.currentJob / logs.stepsLog missing")
	}
	return &v, nil
}

func (w *WebSession) rememberJobs(r RepoRef, runID, runIndex int64, jobs []webJob) {
	w.cmu.Lock()
	defer w.cmu.Unlock()
	if len(w.jobLoc) > webMaxJobs {
		w.jobLoc = map[int64]webJobLoc{}
	}
	for i, j := range jobs {
		w.jobLoc[j.ID] = webJobLoc{RunID: runID, RunIndex: runIndex, JobIndex: i, Repo: r}
	}
}

// ---------------------------------------------------------------------------------------------
// Public features (called by Service methods)
// ---------------------------------------------------------------------------------------------

func (w *WebSession) listJobs(ctx context.Context, r RepoRef, runID int64) ([]Job, error) {
	idx, err := w.runIndex(ctx, r, runID)
	if err != nil {
		return nil, err
	}
	v, err := w.view(ctx, r, idx, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	w.rememberJobs(r, runID, idx, *v.State.Run.Jobs)
	out := make([]Job, 0, len(*v.State.Run.Jobs))
	for _, j := range *v.State.Run.Jobs {
		// The web view does not expose runs-on labels or needs: they stay empty, not invented.
		out = append(out, Job{ID: j.ID, Name: j.Name, Status: j.Status, RunsOn: []string{}})
	}
	return out, nil
}

// JobStep is one step of a job as the Forgejo UI shows it (the runner's "Set up job" and
// "Complete job" bookkeeping steps included).
type JobStep struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Duration string `json:"duration,omitempty"`
}

func (w *WebSession) listSteps(ctx context.Context, r RepoRef, runID int64) (map[int64][]JobStep, error) {
	idx, err := w.runIndex(ctx, r, runID)
	if err != nil {
		return nil, err
	}
	v, err := w.view(ctx, r, idx, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	jobs := *v.State.Run.Jobs
	w.rememberJobs(r, runID, idx, jobs)
	out := map[int64][]JobStep{}
	for i, j := range jobs {
		jv := v
		if i > 0 {
			if jv, err = w.view(ctx, r, idx, i, 0, nil); err != nil {
				return nil, err
			}
		}
		if att := attemptOf(jv); att > 0 { // steps are only served on the attempt URL
			if jv, err = w.view(ctx, r, idx, i, att, nil); err != nil {
				return nil, err
			}
		}
		steps := []JobStep{}
		if jv.State.CurrentJob.Steps != nil {
			for _, s := range *jv.State.CurrentJob.Steps {
				steps = append(steps, JobStep{Name: s.Summary, Status: s.Status, Duration: s.Duration})
			}
		}
		out[j.ID] = steps
	}
	return out, nil
}

// locate finds the (run, job index) of a job id: from the cache ListJobs fills, else by scanning
// the repository's most recent runs.
func (w *WebSession) locate(ctx context.Context, r RepoRef, jobID int64) (webJobLoc, error) {
	w.cmu.Lock()
	loc, ok := w.jobLoc[jobID]
	w.cmu.Unlock()
	if ok && loc.Repo == r {
		return loc, nil
	}
	l, err := w.svc.ListRuns(ctx, r, RunQuery{}, Page{Limit: 30})
	if err != nil {
		return webJobLoc{}, err
	}
	for _, run := range l.Items {
		if _, err := w.listJobs(ctx, r, run.ID); err != nil {
			continue
		}
		w.cmu.Lock()
		loc, ok = w.jobLoc[jobID]
		w.cmu.Unlock()
		if ok && loc.Repo == r {
			return loc, nil
		}
	}
	return webJobLoc{}, &Error{Code: CodeNotFound, Message: "job not found among the repository's recent runs", Op: "GET job logs"}
}

// webLogBuf accumulates a job's log per step so a poll only fetches the NEW lines from Forgejo
// (it sends the per-step cursor the UI uses). Reset when the job is re-run (new attempt).
type webLogBuf struct {
	attempt int64
	names   []string
	status  []string
	lines   [][]string
	cursor  []int64
	bytes   int
	dropped bool
	touched time.Time
	mu      sync.Mutex
}

func (b *webLogBuf) reset(attempt int64) {
	b.attempt, b.names, b.status, b.lines, b.cursor, b.bytes, b.dropped = attempt, nil, nil, nil, nil, 0, false
}

func (b *webLogBuf) grow(n int) {
	for len(b.lines) < n {
		b.names, b.status = append(b.names, ""), append(b.status, "")
		b.lines, b.cursor = append(b.lines, nil), append(b.cursor, 0)
	}
}

func (b *webLogBuf) add(step int, lines []webLine) {
	for _, l := range lines {
		b.lines[step] = append(b.lines[step], l.Message)
		b.bytes += len(l.Message) + 1
	}
	// Past the cap, drop the oldest lines (the tail is what matters, as in JobLogs).
	for b.bytes > webMaxLogBytesJob {
		cut := false
		for i := range b.lines {
			if len(b.lines[i]) > 0 {
				n := min(len(b.lines[i]), 1+len(b.lines[i])/2)
				for _, m := range b.lines[i][:n] {
					b.bytes -= len(m) + 1
				}
				b.lines[i] = append([]string(nil), b.lines[i][n:]...)
				b.dropped, cut = true, true
				break
			}
		}
		if !cut {
			break
		}
	}
}

func (b *webLogBuf) render() string {
	var sb strings.Builder
	for i := range b.lines {
		if len(b.lines[i]) == 0 && b.cursor[i] == 0 {
			continue
		}
		fmt.Fprintf(&sb, "##[step] %s\n", b.names[i])
		for _, l := range b.lines[i] {
			sb.WriteString(l)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

func (w *WebSession) logBuf(jobID int64) *webLogBuf {
	w.cmu.Lock()
	defer w.cmu.Unlock()
	b := w.logs[jobID]
	if b == nil {
		if len(w.logs) >= webMaxLogJobs {
			var oldest int64
			var ot time.Time
			for id, x := range w.logs {
				if oldest == 0 || x.touched.Before(ot) {
					oldest, ot = id, x.touched
				}
			}
			delete(w.logs, oldest)
		}
		b = &webLogBuf{}
		w.logs[jobID] = b
	}
	b.touched = w.svc.now()
	return b
}

func attemptOf(v *webView) int64 {
	var n int64
	if v.State.CurrentJob.AllAttempts != nil {
		for _, a := range *v.State.CurrentJob.AllAttempts {
			n = max(n, a.Number)
		}
	}
	return n
}

func (w *WebSession) jobLogs(ctx context.Context, r RepoRef, jobID int64, maxBytes int) (*Logs, error) {
	loc, err := w.locate(ctx, r, jobID)
	if err != nil {
		return nil, err
	}
	b := w.logBuf(jobID)
	b.mu.Lock()
	defer b.mu.Unlock()
	for round := 0; round < 4; round++ {
		if b.attempt == 0 { // discover the latest attempt (the plain job URL serves no steps/logs)
			v0, err := w.view(ctx, r, loc.RunIndex, loc.JobIndex, 0, nil)
			if err != nil {
				return nil, err
			}
			if b.attempt = attemptOf(v0); b.attempt == 0 {
				break
			}
		}
		cur := make([]webCursor, len(b.lines))
		for i := range cur {
			cur[i] = webCursor{Step: i, Cursor: b.cursor[i], Expanded: true}
		}
		v, err := w.view(ctx, r, loc.RunIndex, loc.JobIndex, b.attempt, cur)
		if err != nil {
			if e, _ := AsError(err); e != nil && e.Code == CodeUpstream && len(cur) > 0 {
				b.reset(0) // e.g. the step list shrank after a re-run: start over
				continue
			}
			return nil, err
		}
		if att := attemptOf(v); att > b.attempt { // the job was re-run: a new attempt, new log
			b.reset(att)
			continue
		}
		var steps []webStep
		if v.State.CurrentJob.Steps != nil {
			steps = *v.State.CurrentJob.Steps
		}
		if len(steps) < len(b.lines) {
			b.reset(b.attempt)
			continue
		}
		known := len(b.lines)
		b.grow(len(steps))
		for i, s := range steps {
			b.names[i], b.status[i] = s.Summary, s.Status
		}
		for _, sl := range *v.Logs.StepsLog {
			if sl.Step < 0 || sl.Step >= len(b.lines) || sl.Cursor < b.cursor[sl.Step] {
				continue
			}
			b.add(sl.Step, sl.Lines)
			b.cursor[sl.Step] = sl.Cursor
		}
		if len(steps) > known && known > 0 {
			continue // new steps appeared: fetch their lines now
		}
		if len(steps) > known && known == 0 {
			continue // first call sent no cursors: fetch every step from 0
		}
		break
	}
	l := &Logs{Content: b.render(), Truncated: b.dropped}
	if maxBytes <= 0 || maxBytes > MaxLogBytes {
		maxBytes = MaxLogBytes
	}
	if len(l.Content) > maxBytes {
		l.Content = strings.ToValidUTF8(l.Content[len(l.Content)-maxBytes:], "")
		l.Truncated = true
	}
	return l, nil
}

func (w *WebSession) cancelRun(ctx context.Context, r RepoRef, runID int64) error {
	idx, err := w.runIndex(ctx, r, runID)
	if err != nil {
		return err
	}
	if _, err := w.do(ctx, "POST /{o}/{r}/actions/runs/{run}/cancel", r, http.MethodPost, w.jobPath(r, idx, "/cancel"), []byte("{}"), "application/json", "application/json", 1<<20, false); err != nil {
		return err
	}
	return nil
}

func (w *WebSession) rerun(ctx context.Context, r RepoRef, runID int64, failedOnly bool) (*Run, error) {
	idx, err := w.runIndex(ctx, r, runID)
	if err != nil {
		return nil, err
	}
	const op = "POST /{o}/{r}/actions/runs/{run}/rerun"
	if !failedOnly {
		if _, err := w.do(ctx, op, r, http.MethodPost, w.jobPath(r, idx, "/rerun"), []byte("{}"), "application/json", "application/json", 1<<20, false); err != nil {
			return nil, err
		}
		return w.svc.GetRun(ctx, r, runID)
	}
	v, err := w.view(ctx, r, idx, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	jobs := *v.State.Run.Jobs
	w.rememberJobs(r, runID, idx, jobs)
	started := 0
	for i, j := range jobs {
		if j.Status != "failure" && j.Status != "cancelled" {
			continue
		}
		// A job re-run also restarts the jobs that need it: those are already waiting when we get to them.
		cv, err := w.view(ctx, r, idx, 0, 0, nil)
		if err == nil {
			cj := *cv.State.Run.Jobs
			if i < len(cj) && cj[i].Status != "failure" && cj[i].Status != "cancelled" {
				continue
			}
		}
		if _, err := w.do(ctx, "POST /{o}/{r}/actions/runs/{run}/jobs/{job}/rerun", r, http.MethodPost, w.jobPath(r, idx, "/jobs/"+itoa(i)+"/rerun"), []byte("{}"), "application/json", "application/json", 1<<20, false); err != nil {
			return nil, err
		}
		started++
	}
	if started == 0 {
		return nil, &Error{Code: CodeConflict, Message: "the run has no failed job to re-run", Op: op}
	}
	return w.svc.GetRun(ctx, r, runID)
}

type webArtifact struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Status string `json:"status"`
}

func (w *WebSession) listArtifacts(ctx context.Context, r RepoRef, runID int64) ([]Artifact, error) {
	idx, err := w.runIndex(ctx, r, runID)
	if err != nil {
		return nil, err
	}
	const op = "GET /{o}/{r}/actions/runs/{run}/artifacts"
	res, err := w.do(ctx, op, r, http.MethodGet, w.jobPath(r, idx, "/artifacts"), nil, "", "application/json", maxResponseBytes, true)
	if err != nil {
		return nil, err
	}
	var env struct {
		Artifacts *[]webArtifact `json:"artifacts"`
	}
	if json.Unmarshal(res.body, &env) != nil || env.Artifacts == nil {
		return nil, shapeErr(op, "artifacts missing")
	}
	out := make([]Artifact, 0, len(*env.Artifacts))
	for _, a := range *env.Artifacts {
		if a.Status == "expired" {
			continue
		}
		out = append(out, Artifact{Name: a.Name, Size: a.Size,
			DownloadURL: w.svc.cfg.URL + "/" + esc(r.Owner) + "/" + esc(r.Repo) + "/actions/runs/" + i64(runID) + "/artifacts/" + esc(a.Name)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (w *WebSession) downloadArtifact(ctx context.Context, r RepoRef, runID int64, name string) ([]byte, error) {
	if name == "" || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return nil, invalid("invalid artifact name")
	}
	// The download route takes the run ID (the list route takes the run number): see the header.
	res, err := w.do(ctx, "GET /{o}/{r}/actions/runs/{runID}/artifacts/{name}", r, http.MethodGet,
		"/"+esc(r.Owner)+"/"+esc(r.Repo)+"/actions/runs/"+i64(runID)+"/artifacts/"+esc(name), nil, "", "application/zip", webMaxArtifact, true)
	if err != nil {
		return nil, err
	}
	return res.body, nil
}
