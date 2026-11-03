package handlers

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

const (
	logChunkLines = 2000
	maxCIValue    = 64 << 10
	maxDispatchIn = 50
)

var (
	ciNameRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	eventRe     = regexp.MustCompile(`^[a-z_]{1,40}$`)
	inputNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	reserved    = []string{"FORGEJO_", "GITEA_", "GITHUB_", "CI"}
)

func validCIName(n string) bool {
	if !ciNameRe.MatchString(n) {
		return false
	}
	u := strings.ToUpper(n)
	for _, p := range reserved {
		if u == p || strings.HasPrefix(u, p) && p != "CI" {
			return false
		}
	}
	return true
}

// ---- workflows ------------------------------------------------------------------------------

// workflowsList: GET .../git/workflows (read from the default branch).
func (a *gitAPI) workflowsList(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitRead)
	if !ok {
		return
	}
	def, repo, err := a.defaultBranch(sc)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	if repo.Empty {
		respondJSON(w, http.StatusOK, map[string]any{"items": []gitapi.WorkflowOut{}})
		return
	}
	items, err := gitapi.ListWorkflows(sc.ctx, sc.core, sc.ref, def)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items})
}

type dispatchIn struct {
	Ref    string            `json:"ref"`
	Inputs map[string]string `json:"inputs"`
}

// workflowDispatch: POST .../git/workflows/{workflowID}/dispatch (Idempotency-Key).
func (a *gitAPI) workflowDispatch(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitWrite)
	if !ok {
		return
	}
	id := pathName(r, "workflowID")
	if !gitapi.ValidWorkflowID(id) {
		badRequest(w, "workflowID must be the workflow file name, e.g. ci.yml")
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	var in dispatchIn
	if !decodeStrict(w, body, &in, false) {
		return
	}
	in.Ref = strings.TrimSpace(in.Ref)
	if !gitsource.ValidBranch(in.Ref) {
		badRequest(w, "ref must be a branch or tag name")
		return
	}
	if len(in.Inputs) > maxDispatchIn {
		badRequest(w, "at most 50 inputs")
		return
	}
	for k, v := range in.Inputs {
		if !inputNameRe.MatchString(k) || len(v) > 4096 {
			badRequest(w, "invalid input name or value (names up to 64 characters, values up to 4 KiB)")
			return
		}
	}
	ctx, ok := a.asUser(w, sc, false)
	if !ok {
		return
	}
	a.withIdempotency(w, r, sc, "workflowDispatch:"+id, body, func(out http.ResponseWriter) {
		if err := sc.core.DispatchWorkflow(ctx, sc.ref, id, in.Ref, in.Inputs); err != nil {
			a.fail(out, err, false)
			return
		}
		out.WriteHeader(http.StatusAccepted)
	})
}

// ---- runs -----------------------------------------------------------------------------------

// runsList: GET .../git/runs
func (a *gitAPI) runsList(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitRead)
	if !ok {
		return
	}
	pg, ok := pageParams(w, r)
	if !ok {
		return
	}
	qv := r.URL.Query()
	wf, branch, status, event := qv.Get("workflow"), qv.Get("branch"), qv.Get("status"), qv.Get("event")
	switch {
	case wf != "" && !gitapi.ValidWorkflowID(wf):
		badRequest(w, "invalid workflow")
		return
	case branch != "" && !gitsource.ValidBranch(branch):
		badRequest(w, "invalid branch")
		return
	case event != "" && !eventRe.MatchString(event):
		badRequest(w, "invalid event")
		return
	}
	q := gitcore.RunQuery{Event: event, Ref: branch}
	clientStatus := ""
	if status != "" {
		switch status {
		case "queued", "running", "success", "failure", "cancelled":
			q.Status, _ = gitapi.ForgejoRunStatus(status)
		case "waiting_approval":
			clientStatus = status
		default:
			badRequest(w, "status must be queued, running, success, failure, cancelled or waiting_approval")
			return
		}
	}
	l, err := sc.core.ListRuns(sc.ctx, sc.ref, q, pg)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	items := make([]gitapi.RunOut, 0, len(l.Items))
	for _, run := range l.Items {
		if wf != "" && run.WorkflowID != wf { // Forgejo has no workflow filter: applied on the page
			continue
		}
		o := gitapi.ToRun(run)
		if clientStatus != "" && o.Status != clientStatus {
			continue
		}
		items = append(items, o)
	}
	respondJSON(w, http.StatusOK, newList(items, l.NextCursor))
}

func (a *gitAPI) runScope(w http.ResponseWriter, r *http.Request, act authz.Action) (*gitScope, int64, bool) {
	sc, ok := a.scope(w, r, act)
	if !ok {
		return nil, 0, false
	}
	id, ok := pathInt64(r, "runID")
	if !ok {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid run id")
		return nil, 0, false
	}
	return sc, id, true
}

// runGet: GET .../git/runs/{runID} (with its jobs)
func (a *gitAPI) runGet(w http.ResponseWriter, r *http.Request) {
	sc, id, ok := a.runScope(w, r, authz.GitRead)
	if !ok {
		return
	}
	run, err := sc.core.GetRun(sc.ctx, sc.ref, id)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	out := gitapi.ToRun(*run)
	// Jobs and steps come from the Forgejo web session. Without it (or when Forgejo rejects it) the
	// run is still returned, with the reason, instead of failing the whole page.
	jobs, err := sc.core.ListJobs(sc.ctx, sc.ref, id)
	switch {
	case gitcore.IsUnsupported(err):
		out.JobsUnavailable = err.Error()
		if e, ok := gitcore.AsError(err); ok {
			out.JobsUnavailable = e.Message
		}
	case err != nil:
		a.fail(w, err, false)
		return
	default:
		out.Jobs = gitapi.ToRunJobs(jobs)
		if sl, ok := sc.core.(gitcore.JobStepLister); ok {
			if steps, err := sl.ListJobSteps(sc.ctx, sc.ref, id); err == nil {
				gitapi.AttachSteps(out.Jobs, steps)
			}
		}
	}
	respondJSON(w, http.StatusOK, out)
}

type logChunk struct {
	Lines      []string `json:"lines"`
	Complete   bool     `json:"complete"`
	NextCursor *string  `json:"next_cursor"`
}

// jobLogs: GET .../git/runs/{runID}/jobs/{jobID}/logs?cursor=. The log is redacted before it leaves
// the API and served in chunks of 2000 lines; the cursor is the line offset. complete is true when
// the job finished and there is nothing left to read.
func (a *gitAPI) jobLogs(w http.ResponseWriter, r *http.Request) {
	sc, runID, ok := a.runScope(w, r, authz.GitRead)
	if !ok {
		return
	}
	jobID, ok := pathInt64(r, "jobID")
	if !ok {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid job id")
		return
	}
	off, err := gitapi.ParseOffset(r.URL.Query().Get("cursor"))
	if err != nil {
		a.fail(w, err, false)
		return
	}
	jobs, err := sc.core.ListJobs(sc.ctx, sc.ref, runID)
	if err != nil {
		a.failExt(w, err)
		return
	}
	var job *gitcore.Job
	for i := range jobs {
		if jobs[i].ID == jobID {
			job = &jobs[i]
			break
		}
	}
	if job == nil { // also stops reading the log of a job that belongs to another run
		respondError(w, http.StatusNotFound, "NOT_FOUND", "job not found in this run")
		return
	}
	logs, err := sc.core.JobLogs(sc.ctx, sc.ref, jobID, gitcore.MaxLogBytes)
	if err != nil {
		a.failExt(w, err)
		return
	}
	text := gitapi.RedactLog(logs.Content)
	lines := strings.Split(strings.TrimRight(strings.ReplaceAll(text, "\r\n", "\n"), "\n"), "\n")
	if text == "" {
		lines = []string{}
	}
	if logs.Truncated {
		lines = append([]string{"[log truncated: showing only the last part]"}, lines...)
	}
	if off > len(lines) {
		off = len(lines)
	}
	end := off + logChunkLines
	out := logChunk{}
	if end < len(lines) {
		n := gitapi.OffsetCursor(end)
		out.NextCursor = &n
	} else {
		end = len(lines)
	}
	out.Lines = lines[off:end]
	out.Complete = out.NextCursor == nil && gitapi.JobFinished(job.Status)
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusOK, out)
}

// runRerun: POST .../git/runs/{runID}/rerun?failed= (Idempotency-Key).
func (a *gitAPI) runRerun(w http.ResponseWriter, r *http.Request) {
	sc, id, ok := a.runScope(w, r, authz.GitWrite)
	if !ok {
		return
	}
	failed := false
	if v := r.URL.Query().Get("failed"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			badRequest(w, "failed must be true or false")
			return
		}
		failed = b
	}
	rr, ok := extOf[gitapi.RunRerunner](sc.core)
	if !ok {
		notSupported(w, "re-running a workflow run")
		return
	}
	ctx, ok := a.asUser(w, sc, false)
	if !ok {
		return
	}
	a.withIdempotency(w, r, sc, "runRerun:"+strconv.FormatInt(id, 10)+":"+strconv.FormatBool(failed), nil, func(out http.ResponseWriter) {
		run, err := rr.RerunRun(ctx, sc.ref, id, failed)
		if err != nil {
			a.failExt(out, err)
			return
		}
		respondJSON(out, http.StatusAccepted, gitapi.ToRun(*run))
	})
}

// runCancel: POST .../git/runs/{runID}/cancel
func (a *gitAPI) runCancel(w http.ResponseWriter, r *http.Request) {
	sc, id, ok := a.runScope(w, r, authz.GitWrite)
	if !ok {
		return
	}
	ctx, ok := a.asUser(w, sc, false)
	if !ok {
		return
	}
	if err := sc.core.CancelRun(ctx, sc.ref, id); err != nil {
		a.failExt(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// artifactsList: GET .../git/runs/{runID}/artifacts
func (a *gitAPI) artifactsList(w http.ResponseWriter, r *http.Request) {
	sc, id, ok := a.runScope(w, r, authz.GitRead)
	if !ok {
		return
	}
	al, ok := extOf[gitapi.ArtifactLister](sc.core)
	if !ok {
		notSupported(w, "listing run artifacts")
		return
	}
	items, err := al.ListArtifacts(sc.ctx, sc.ref, id)
	if err != nil {
		a.failExt(w, err)
		return
	}
	if items == nil {
		items = []gitapi.Artifact{}
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items})
}

// ---- secrets and variables ------------------------------------------------------------------

type ciItem struct {
	Name      string `json:"name"`
	Scope     string `json:"scope"`
	Value     string `json:"value,omitempty"`
	UpdatedAt any    `json:"updated_at,omitempty"`
}

func (a *gitAPI) listSecrets(w http.ResponseWriter, sc *gitScope, ref gitcore.RepoRef, scopeName string) {
	sl, ok := extOf[gitapi.SecretLister](sc.core)
	if !ok {
		notSupported(w, "listing secrets")
		return
	}
	list, err := sl.ListSecrets(sc.ctx, ref)
	if err != nil {
		a.failExt(w, err)
		return
	}
	items := make([]ciItem, 0, len(list)) // names only: a secret value is never readable
	for _, s := range list {
		it := ciItem{Name: s.Name, Scope: scopeName}
		if !s.UpdatedAt.IsZero() {
			it.UpdatedAt = s.UpdatedAt
		}
		items = append(items, it)
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items})
}

type ciValueIn struct {
	Value string `json:"value"`
}

func (a *gitAPI) readCIValue(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	if !validCIName(name) {
		badRequest(w, "name must match [A-Za-z_][A-Za-z0-9_]* (up to 64 characters) and not start with FORGEJO_, GITEA_ or GITHUB_")
		return "", false
	}
	var in ciValueIn
	if !a.readJSON(w, r, &in, false) {
		return "", false
	}
	if in.Value == "" || !validText(in.Value, maxCIValue) {
		badRequest(w, "value is required (at most 64 KiB)")
		return "", false
	}
	return in.Value, true
}

func (a *gitAPI) putSecret(w http.ResponseWriter, r *http.Request, sc *gitScope, ref gitcore.RepoRef) {
	name := pathName(r, "name")
	val, ok := a.readCIValue(w, r, name)
	if !ok {
		return
	}
	if err := sc.core.SetSecret(sc.ctx, ref, name, val); err != nil {
		a.fail(w, err, false)
		return
	}
	a.lg.Info("git api: secret written", "repo", ref.String(), "name", name, "user_id", userIDString(sc)) // never the value
	respondNoContent(w)
}

func (a *gitAPI) deleteSecret(w http.ResponseWriter, r *http.Request, sc *gitScope, ref gitcore.RepoRef) {
	name := pathName(r, "name")
	if !validCIName(name) {
		badRequest(w, "invalid secret name")
		return
	}
	if err := sc.core.DeleteSecret(sc.ctx, ref, name); err != nil {
		a.fail(w, err, false)
		return
	}
	a.lg.Info("git api: secret deleted", "repo", ref.String(), "name", name, "user_id", userIDString(sc))
	respondNoContent(w)
}

func userIDString(sc *gitScope) string {
	if sc.user == nil {
		return ""
	}
	return sc.user.ID.String()
}

func (a *gitAPI) putVar(w http.ResponseWriter, r *http.Request, sc *gitScope, ref gitcore.RepoRef) {
	name := pathName(r, "name")
	val, ok := a.readCIValue(w, r, name)
	if !ok {
		return
	}
	if err := sc.core.SetVariable(sc.ctx, ref, name, val); err != nil {
		a.fail(w, err, false)
		return
	}
	respondNoContent(w)
}

func (a *gitAPI) deleteVar(w http.ResponseWriter, r *http.Request, sc *gitScope, ref gitcore.RepoRef) {
	name := pathName(r, "name")
	if !validCIName(name) {
		badRequest(w, "invalid variable name")
		return
	}
	if err := sc.core.DeleteVariable(sc.ctx, ref, name); err != nil {
		a.fail(w, err, false)
		return
	}
	respondNoContent(w)
}

func (a *gitAPI) ciSecretsList(w http.ResponseWriter, r *http.Request) {
	if sc, ok := a.scope(w, r, authz.GitAdmin); ok {
		a.listSecrets(w, sc, sc.ref, "repo")
	}
}

func (a *gitAPI) ciSecretPut(w http.ResponseWriter, r *http.Request) {
	if sc, ok := a.scope(w, r, authz.GitAdmin); ok {
		a.putSecret(w, r, sc, sc.ref)
	}
}

func (a *gitAPI) ciSecretDelete(w http.ResponseWriter, r *http.Request) {
	if sc, ok := a.scope(w, r, authz.GitAdmin); ok {
		a.deleteSecret(w, r, sc, sc.ref)
	}
}

// ciVarsList: repository variables plus the organization ones they do not shadow.
func (a *gitAPI) ciVarsList(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitRead)
	if !ok {
		return
	}
	vars, err := sc.core.ListVariables(sc.ctx, sc.ref)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	items := make([]ciItem, 0, len(vars))
	seen := map[string]bool{}
	for _, v := range vars {
		seen[v.Name] = true
		items = append(items, ciItem{Name: v.Name, Scope: "repo", Value: v.Value})
	}
	if orgVars, err := sc.core.ListVariables(sc.ctx, gitcore.RepoRef{Owner: sc.ref.Owner}); err == nil {
		for _, v := range orgVars {
			if !seen[v.Name] {
				items = append(items, ciItem{Name: v.Name, Scope: "org", Value: v.Value})
			}
		}
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *gitAPI) ciVarPut(w http.ResponseWriter, r *http.Request) {
	if sc, ok := a.scope(w, r, authz.GitAdmin); ok {
		a.putVar(w, r, sc, sc.ref)
	}
}

func (a *gitAPI) ciVarDelete(w http.ResponseWriter, r *http.Request) {
	if sc, ok := a.scope(w, r, authz.GitAdmin); ok {
		a.deleteVar(w, r, sc, sc.ref)
	}
}

func (a *gitAPI) orgCiSecretsList(w http.ResponseWriter, r *http.Request) {
	if sc, ok := a.orgScope(w, r, true); ok {
		a.listSecrets(w, sc, sc.ref, "org")
	}
}

func (a *gitAPI) orgCiSecretPut(w http.ResponseWriter, r *http.Request) {
	if sc, ok := a.orgScope(w, r, true); ok {
		a.putSecret(w, r, sc, sc.ref)
	}
}

func (a *gitAPI) orgCiSecretDelete(w http.ResponseWriter, r *http.Request) {
	if sc, ok := a.orgScope(w, r, true); ok {
		a.deleteSecret(w, r, sc, sc.ref)
	}
}

func (a *gitAPI) orgCiVarsList(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.orgScope(w, r, false)
	if !ok {
		return
	}
	vars, err := sc.core.ListVariables(sc.ctx, sc.ref)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	items := make([]ciItem, 0, len(vars))
	for _, v := range vars {
		items = append(items, ciItem{Name: v.Name, Scope: "org", Value: v.Value})
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *gitAPI) orgCiVarPut(w http.ResponseWriter, r *http.Request) {
	if sc, ok := a.orgScope(w, r, true); ok {
		a.putVar(w, r, sc, sc.ref)
	}
}

func (a *gitAPI) orgCiVarDelete(w http.ResponseWriter, r *http.Request) {
	if sc, ok := a.orgScope(w, r, true); ok {
		a.deleteVar(w, r, sc, sc.ref)
	}
}

// runnersList: GET /orgs/{orgID}/git/runners
func (a *gitAPI) runnersList(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.orgScope(w, r, false)
	if !ok {
		return
	}
	rl, ok := extOf[gitapi.RunnerLister](sc.core)
	if !ok {
		notSupported(w, "listing runners")
		return
	}
	items, err := rl.ListRunners(sc.ctx, sc.org.Slug)
	if err != nil {
		a.failExt(w, err)
		return
	}
	if items == nil {
		items = []gitapi.Runner{}
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items})
}
