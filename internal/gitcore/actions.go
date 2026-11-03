package gitcore

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func i64(n int64) string { return strconv.FormatInt(n, 10) }

type fgRun struct {
	ID           int64  `json:"id"`
	Index        int64  `json:"index_in_repo"`
	WorkflowID   string `json:"workflow_id"`
	Title        string `json:"title"`
	Event        string `json:"event"`
	PrettyRef    string `json:"prettyref"`
	CommitSHA    string `json:"commit_sha"`
	Status       string `json:"status"`
	NeedApproval bool   `json:"need_approval"`
	TriggerUser  fgUser `json:"trigger_user"`
	Started      string `json:"started"`
	Stopped      string `json:"stopped"`
	HTMLURL      string `json:"html_url"`
}

func (f fgRun) run() Run {
	return Run{ID: f.ID, Index: f.Index, WorkflowID: f.WorkflowID, Title: f.Title, Event: f.Event, Ref: f.PrettyRef, SHA: f.CommitSHA,
		Status: f.Status, NeedApproval: f.NeedApproval, Actor: f.TriggerUser.person(), StartedAt: parseTime(f.Started),
		StoppedAt: parseTime(f.Stopped), HTMLURL: f.HTMLURL}
}

func (s *Service) ListRuns(ctx context.Context, r RepoRef, q RunQuery, p Page) (List[Run], error) {
	if err := r.valid(); err != nil {
		return List[Run]{}, err
	}
	qv := url.Values{}
	if q.Status != "" {
		qv.Set("status", q.Status)
	}
	if q.Event != "" {
		qv.Set("event", q.Event)
	}
	if q.Ref != "" {
		qv.Set("ref", q.Ref)
	}
	if q.HeadSHA != "" {
		qv.Set("head_sha", q.HeadSHA)
	}
	decode := func(b []byte) ([]fgRun, error) {
		var env struct {
			Runs []fgRun `json:"workflow_runs"`
		}
		err := jsonInto(b, &env)
		return env.Runs, err
	}
	key := s.listKey(ctx, r, "runs", q.Status, q.Event, q.Ref, q.HeadSHA, p.Cursor, itoa(clampLimit(p.Limit)))
	// Runs change quickly: a short cache (invalidated by webhook) is enough to absorb polling.
	return cached(ctx, s, key, minDur(s.cfg.ListTTL, 5_000_000_000), func() (List[Run], error) {
		items, next, err := fetchPaged[fgRun](ctx, s, req{method: http.MethodGet, path: r.base() + "/actions/runs", op: "/repos/{o}/{r}/actions/runs", query: qv}, p, "", decode)
		if err != nil {
			return List[Run]{}, err
		}
		out := List[Run]{Items: make([]Run, 0, len(items)), NextCursor: next}
		for _, f := range items {
			out.Items = append(out.Items, f.run())
		}
		return out, nil
	})
}

func (s *Service) GetRun(ctx context.Context, r RepoRef, id int64) (*Run, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	var f fgRun
	if _, err := s.do(ctx, req{method: http.MethodGet, path: r.base() + "/actions/runs/" + i64(id), op: "/repos/{o}/{r}/actions/runs/{id}"}, &f); err != nil {
		return nil, err
	}
	run := f.run()
	return &run, nil
}

// ListJobs, JobLogs and CancelRun are NOT in Forgejo v15.0.11 REST API (every such endpoint answers 404):
// they use the web-session client (websession.go). Without CAPSULE_GIT_BOT_PASSWORD they answer
// CodeUnsupported (NOT_SUPPORTED) with the reason and the Forgejo link.
func (s *Service) ListJobs(ctx context.Context, r RepoRef, runID int64) ([]Job, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if s.web == nil {
		return nil, s.webOff("list the jobs of a run", r)
	}
	return s.web.listJobs(ctx, r, runID)
}

func (s *Service) JobLogs(ctx context.Context, r RepoRef, jobID int64, maxBytes int) (*Logs, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if s.web == nil {
		return nil, s.webOff("read a job log", r)
	}
	return s.web.jobLogs(ctx, r, jobID, maxBytes)
}

func (s *Service) CancelRun(ctx context.Context, r RepoRef, id int64) error {
	if err := r.valid(); err != nil {
		return err
	}
	if s.web == nil {
		return s.webOff("cancel a run", r)
	}
	err := s.web.cancelRun(ctx, r, id)
	if err == nil {
		_ = s.InvalidateRepo(ctx, r)
	}
	return err
}

func (s *Service) DispatchWorkflow(ctx context.Context, r RepoRef, workflow, ref string, inputs map[string]string) error {
	if err := r.valid(); err != nil {
		return err
	}
	if workflow == "" || ref == "" {
		return invalid("workflow file and ref are required")
	}
	body := map[string]any{"ref": ref}
	if len(inputs) > 0 {
		body["inputs"] = inputs
	}
	_, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/actions/workflows/" + esc(workflow) + "/dispatches", op: "/repos/{o}/{r}/actions/workflows/{wf}/dispatches", body: body}, nil)
	if err == nil {
		_ = s.InvalidateRepo(ctx, r)
	}
	return err
}

// scope returns the Actions base path: the repository, or the organization when r.Repo == "".
func scope(r RepoRef) (path, tmpl string, err error) {
	if r.Owner == "" || strings.ContainsAny(r.Owner+r.Repo, "/\\?#%") || r.Owner == "." || r.Owner == ".." {
		return "", "", &Error{Code: CodeInvalid, Message: "invalid repository reference"}
	}
	if r.Repo == "" {
		return "/orgs/" + esc(r.Owner), "/orgs/{o}", nil
	}
	if err := r.valid(); err != nil {
		return "", "", err
	}
	return r.base(), "/repos/{o}/{r}", nil
}

func (s *Service) ListVariables(ctx context.Context, r RepoRef) ([]Variable, error) {
	base, tmpl, err := scope(r)
	if err != nil {
		return nil, err
	}
	out := []Variable{}
	cur := ""
	for i := 0; i < 10; i++ {
		items, next, err := fetchPaged[struct {
			Name string `json:"name"`
			Data string `json:"data"`
		}](ctx, s, req{method: http.MethodGet, path: base + "/actions/variables", op: tmpl + "/actions/variables"}, Page{Cursor: cur, Limit: MaxLimit}, "", nil)
		if err != nil {
			return nil, err
		}
		for _, v := range items {
			out = append(out, Variable{Name: v.Name, Value: v.Data})
		}
		if next == "" {
			break
		}
		cur = next
	}
	return out, nil
}

func validName(n string) bool {
	if n == "" || len(n) > 255 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func (s *Service) SetVariable(ctx context.Context, r RepoRef, name, value string) error {
	base, tmpl, err := scope(r)
	if err != nil {
		return err
	}
	if !validName(name) {
		return invalid("variable name may only contain letters, digits and underscore")
	}
	path := base + "/actions/variables/" + esc(name)
	op := tmpl + "/actions/variables/{name}"
	// (?) Forgejo: PUT updates, POST creates. Try update first, create on 404.
	_, err = s.do(ctx, req{method: http.MethodPut, path: path, op: op, body: map[string]any{"value": value}}, nil)
	if errIs(err, CodeNotFound) {
		_, err = s.do(ctx, req{method: http.MethodPost, path: path, op: op, body: map[string]any{"value": value}}, nil)
	}
	return err
}

func (s *Service) DeleteVariable(ctx context.Context, r RepoRef, name string) error {
	base, tmpl, err := scope(r)
	if err != nil {
		return err
	}
	if !validName(name) {
		return invalid("invalid variable name")
	}
	_, err = s.do(ctx, req{method: http.MethodDelete, path: base + "/actions/variables/" + esc(name), op: tmpl + "/actions/variables/{name}"}, nil)
	return err
}

func (s *Service) SetSecret(ctx context.Context, r RepoRef, name, value string) error {
	base, tmpl, err := scope(r)
	if err != nil {
		return err
	}
	if !validName(name) {
		return invalid("secret name may only contain letters, digits and underscore")
	}
	_, err = s.do(ctx, req{method: http.MethodPut, path: base + "/actions/secrets/" + esc(name), op: tmpl + "/actions/secrets/{name}", body: map[string]any{"data": value}}, nil)
	return err
}

func (s *Service) DeleteSecret(ctx context.Context, r RepoRef, name string) error {
	base, tmpl, err := scope(r)
	if err != nil {
		return err
	}
	if !validName(name) {
		return invalid("invalid secret name")
	}
	_, err = s.do(ctx, req{method: http.MethodDelete, path: base + "/actions/secrets/" + esc(name), op: tmpl + "/actions/secrets/{name}"}, nil)
	return err
}
