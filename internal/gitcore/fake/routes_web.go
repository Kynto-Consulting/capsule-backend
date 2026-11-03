package fake

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Web routes of Forgejo's UI that the web-session features use (gitcore/websession.go): login,
// the run view/state POST, cancel, re-run, artifacts. THIS IS A DOUBLE of what Forgejo 15.0.11
// does, written from its source (routers/web/repo/actions/view.go) and checked against a real
// instance by itest/web_test.go; it is not Forgejo's behaviour.

const (
	// BotLogin / BotPassword are the service-account credentials the fake web login accepts.
	BotLogin    = "capsule-bot"
	BotPassword = "fake-bot-password-0123"
	csrfToken   = "fake-csrf-token" // only to exercise the form parsing: 15.0.11 itself has none
)

type fakeArtifact struct {
	Name    string
	Content string
	Expired bool
}

type webState struct {
	breakShape bool
	sessions   map[string]bool
	logins     int
	attempts   map[int64]int64 // job id -> latest attempt (default 1)
	artifacts  map[string][]fakeArtifact
	seq        int
}

func (w *webState) init() {
	if w.sessions == nil {
		w.sessions = map[string]bool{}
		w.attempts = map[int64]int64{}
		w.artifacts = map[string][]fakeArtifact{}
	}
}

// ExpireSessions invalidates every logged-in web session (the next web call must log in again).
func (s *Server) ExpireSessions() {
	s.mu.Lock()
	s.web.init()
	s.web.sessions = map[string]bool{}
	s.mu.Unlock()
}

// WebLogins is how many successful web logins the fake served.
func (s *Server) WebLogins() int { s.mu.Lock(); defer s.mu.Unlock(); return s.web.logins }

// SetLog replaces the log of a job (to simulate a running job that keeps writing).
func (s *Server) SetLog(owner, name string, jobID int64, log string) {
	s.mu.Lock()
	s.repos[owner+"/"+name].Logs[jobID] = log
	s.mu.Unlock()
}

// AddArtifact attaches an artifact to a run.
func (s *Server) AddArtifact(owner, name string, runID int64, art, content string) {
	s.mu.Lock()
	s.web.init()
	k := owner + "/" + name + "#" + strconv.FormatInt(runID, 10)
	s.web.artifacts[k] = append(s.web.artifacts[k], fakeArtifact{Name: art, Content: content})
	s.mu.Unlock()
}

func finishedStatus(st string) bool {
	switch st {
	case "success", "failure", "cancelled", "skipped":
		return true
	}
	return false
}

func jsonMsg(w http.ResponseWriter, code int, m string) {
	writeJSON(w, code, map[string]string{"errorMessage": m})
}

func str2(v any) string { s, _ := v.(string); return s }

func parseForm(body string) map[string]string {
	out := map[string]string{}
	vals, _ := url.ParseQuery(body)
	for k := range vals {
		out[k] = vals.Get(k)
	}
	return out
}

// serveWeb handles every non-API path.
func (s *Server) serveWeb(w http.ResponseWriter, r *http.Request, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.web.init()
	path := r.URL.Path
	session := func() bool {
		c, err := r.Cookie("fgsess")
		return err == nil && s.web.sessions[c.Value]
	}
	switch {
	case path == "/user/login" && r.Method == http.MethodGet:
		http.SetCookie(w, &http.Cookie{Name: "fgpre", Value: "x", Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<form><input type="hidden" name="_csrf" value="%s"></form>`, csrfToken)
		return
	case path == "/user/login" && r.Method == http.MethodPost:
		vals := parseForm(body)
		if vals["_csrf"] == csrfToken && vals["user_name"] == BotLogin && vals["password"] == BotPassword {
			s.web.seq++
			s.web.logins++
			id := "sess-" + strconv.Itoa(s.web.seq)
			s.web.sessions[id] = true
			http.SetCookie(w, &http.Cookie{Name: "fgsess", Value: id, Path: "/"})
			w.Header().Set("Location", "/")
			w.WriteHeader(303)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<p>invalid credentials</p>")
		return
	case path == "/user/settings":
		if !session() {
			w.Header().Set("Location", "/user/login")
			w.WriteHeader(303)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<p>settings</p>")
		return
	}
	// /{o}/{r}/actions/runs/{idx}/...
	p := strings.Split(strings.Trim(path, "/"), "/")
	if len(p) < 5 || p[2] != "actions" || p[3] != "runs" {
		http.NotFound(w, r)
		return
	}
	if !session() { // Forgejo answers 404 to anonymous users on private repositories
		http.NotFound(w, r)
		return
	}
	rp := s.repos[p[0]+"/"+p[1]]
	idx, _ := strconv.Atoi(p[4])
	if rp == nil || idx < 1 || idx > len(rp.Runs) {
		http.NotFound(w, r)
		return
	}
	run := rp.Runs[idx-1]
	runID := int64(idx)
	jobs := rp.Jobs[runID]
	rest := p[5:]
	akey := p[0] + "/" + p[1] + "#" + strconv.FormatInt(runID, 10)
	switch {
	case len(rest) >= 2 && rest[0] == "jobs" && (len(rest) == 2 || rest[2] == "attempt") && r.Method == http.MethodPost:
		s.webView(w, run, jobs, rp, rest, body)
	case len(rest) == 1 && rest[0] == "cancel" && r.Method == http.MethodPost:
		run["status"] = "cancelled"
		for _, j := range jobs {
			if !finishedStatus(str2(j["status"])) {
				j["status"] = "cancelled"
			}
		}
		writeJSON(w, 200, map[string]any{})
	case len(rest) == 1 && rest[0] == "rerun" && r.Method == http.MethodPost:
		if !finishedStatus(str2(run["status"])) {
			jsonMsg(w, 400, "The workflow is still running and cannot be re-run")
			return
		}
		run["status"] = "waiting"
		for _, j := range jobs {
			j["status"] = "waiting"
			s.web.bump(j["id"].(int64))
		}
		writeJSON(w, 200, map[string]string{"redirect": path})
	case len(rest) == 3 && rest[0] == "jobs" && rest[2] == "rerun" && r.Method == http.MethodPost:
		n, _ := strconv.Atoi(rest[1])
		if n < 0 || n >= len(jobs) {
			n = 0
		}
		if !finishedStatus(str2(jobs[n]["status"])) {
			jsonMsg(w, 400, "The job is still running and cannot be re-run")
			return
		}
		jobs[n]["status"] = "waiting"
		run["status"] = "waiting"
		s.web.bump(jobs[n]["id"].(int64))
		writeJSON(w, 200, map[string]string{"redirect": path})
	case len(rest) == 1 && rest[0] == "artifacts" && r.Method == http.MethodGet:
		items := []map[string]any{}
		for _, a := range s.web.artifacts[akey] {
			st := "completed"
			if a.Expired {
				st = "expired"
			}
			items = append(items, map[string]any{"name": a.Name, "size": len(a.Content), "status": st})
		}
		writeJSON(w, 200, map[string]any{"artifacts": items})
	case len(rest) == 2 && rest[0] == "artifacts" && r.Method == http.MethodGet:
		for _, a := range s.web.artifacts[akey] {
			if a.Name == rest[1] {
				var buf bytes.Buffer
				zw := zip.NewWriter(&buf)
				f, _ := zw.Create("file.txt")
				_, _ = f.Write([]byte(a.Content))
				_ = zw.Close()
				w.Header().Set("Content-Type", "application/zip")
				_, _ = w.Write(buf.Bytes())
				return
			}
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) webView(w http.ResponseWriter, run map[string]any, jobs []map[string]any, rp *repo, rest []string, body string) {
	if s.web.breakShape {
		writeJSON(w, 200, map[string]any{"state": map[string]any{}})
		return
	}
	n, _ := strconv.Atoi(rest[1])
	if n < 0 || n >= len(jobs) {
		n = 0
	}
	job := jobs[n]
	jobID := job["id"].(int64)
	att := s.web.attempts[jobID]
	if att == 0 {
		att = 1
	}
	vj := []map[string]any{}
	done := true
	for _, j := range jobs {
		if !finishedStatus(str2(j["status"])) {
			done = false
		}
		vj = append(vj, map[string]any{"id": j["id"], "name": j["name"], "status": j["status"], "canRerun": finishedStatus(str2(j["status"])), "duration": "1s"})
	}
	steps := []map[string]any{}
	var lines []string
	// like Forgejo: the plain job URL (no attempt) serves no task, hence no steps or logs
	if len(rest) == 4 {
		a, _ := strconv.Atoi(rest[3])
		if int64(a) == att && str2(job["status"]) != "waiting" {
			steps = append(steps, map[string]any{"summary": job["name"], "duration": "1s", "status": job["status"]})
			for _, l := range strings.Split(rp.Logs[jobID], "\n") {
				if l != "" {
					lines = append(lines, l)
				}
			}
		}
	}
	type stepLog struct {
		Step   int              `json:"step"`
		Cursor int              `json:"cursor"`
		Lines  []map[string]any `json:"lines"`
	}
	logs := []stepLog{}
	var rq struct {
		LogCursors []struct {
			Step     int  `json:"step"`
			Cursor   int  `json:"cursor"`
			Expanded bool `json:"expanded"`
		} `json:"logCursors"`
	}
	_ = json.Unmarshal([]byte(body), &rq)
	for _, c := range rq.LogCursors {
		if !c.Expanded {
			continue
		}
		if c.Step < 0 || c.Step >= len(steps) {
			http.Error(w, "index out of range", 500)
			return
		}
		sl := stepLog{Step: c.Step, Cursor: c.Cursor, Lines: []map[string]any{}}
		for i := c.Cursor; i < len(lines); i++ {
			sl.Lines = append(sl.Lines, map[string]any{"index": i + 1, "message": lines[i], "timestamp": 1.0})
			sl.Cursor = i + 1
		}
		logs = append(logs, sl)
	}
	writeJSON(w, 200, map[string]any{
		"state": map[string]any{
			"run":        map[string]any{"status": run["status"], "canCancel": !done, "canRerun": done, "done": done, "jobs": vj},
			"currentJob": map[string]any{"title": job["name"], "steps": steps, "allAttempts": []map[string]any{{"number": att}}},
		},
		"logs": map[string]any{"stepsLog": logs},
	})
}

// BreakWebShape makes the run view answer with a different JSON shape (a Forgejo release that
// changed its internal route), to prove gitcore fails loudly instead of guessing.
func (s *Server) BreakWebShape(on bool) {
	s.mu.Lock()
	s.web.init()
	s.web.breakShape = on
	s.mu.Unlock()
}

// SetRunStatus sets the status of a run and all its jobs (a runner picking the run up).
func (s *Server) SetRunStatus(owner, name string, runID int64, status string) {
	s.mu.Lock()
	rp := s.repos[owner+"/"+name]
	rp.Runs[runID-1]["status"] = status
	for _, j := range rp.Jobs[runID] {
		j["status"] = status
	}
	s.mu.Unlock()
}

// bump starts a new attempt of a job (the first attempt is 1).
func (w *webState) bump(job int64) {
	if w.attempts[job] == 0 {
		w.attempts[job] = 1
	}
	w.attempts[job]++
}
