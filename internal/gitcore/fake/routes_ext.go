package fake

import (
	"hash/fnv"
	"net/http"
	"sort"
	"strconv"
)

// Routes added for the integrator additions (gitcore/ext.go): secret names, runners, team patch,
// user lookup by login, tag protection. Same caveat as the rest of the package: this is a double.
// Note what the REAL Forgejo v15.0.11 does not have and therefore this fake does not either:
// re-run, run artifacts, jobs, job logs and cancel endpoints (see gitcore/ext.go).

type fakeRunner struct {
	ID                int64
	Name, Status      string
	Labels            []string
	OwnerID, RepoID   int64
	Scope, Owner, Rep string // scope: repo|org|global
}

type extState struct {
	orgSecrets map[string]map[string]bool
	runners    []fakeRunner
	tagProt    map[string][]map[string]any // "owner/repo" -> rules
	tagSeq     int64
}

func (e *extState) putOrgSecret(org, name string) {
	if e.orgSecrets == nil {
		e.orgSecrets = map[string]map[string]bool{}
	}
	if e.orgSecrets[org] == nil {
		e.orgSecrets[org] = map[string]bool{}
	}
	e.orgSecrets[org][name] = true
}

// AddRunner registers a runner. scope is repo (owner+repo), org (owner) or global.
// status is Forgejo's: idle|active|offline.
func (s *Server) AddRunner(scope, owner, repo, name, status string, labels ...string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := int64(len(s.ext.runners) + 1)
	rn := fakeRunner{ID: id, Name: name, Status: status, Labels: labels, Scope: scope, Owner: owner, Rep: repo}
	switch scope {
	case "repo":
		rn.RepoID = 1
	case "org":
		rn.OwnerID = 1
	}
	s.ext.runners = append(s.ext.runners, rn)
	return id
}

// HasTagProtection reports whether a rule with that pattern exists.
func (s *Server) HasTagProtection(owner, repo, pattern string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.ext.tagProt[owner+"/"+repo] {
		if r["name_pattern"] == pattern {
			return true
		}
	}
	return false
}

func userID(login string) int64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(login))
	return int64(h.Sum32()%1000000) + 1
}

func (s *Server) extRoutes(h func(string, func(http.ResponseWriter, *http.Request)), a string) {
	// ---- secret names (values are never returned)
	h("GET "+a+"/repos/{o}/{r}/actions/secrets", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			names := []string{}
			for n := range rp.Secrets {
				names = append(names, n)
			}
			sort.Strings(names)
			out := []map[string]any{}
			for _, n := range paginate(w, r, names, s.Max) {
				out = append(out, map[string]any{"name": n, "created_at": "2026-11-02T12:00:00Z"})
			}
			writeJSON(w, 200, out)
		}
	})
	h("GET "+a+"/orgs/{o}/actions/secrets", func(w http.ResponseWriter, r *http.Request) {
		if !s.orgs[r.PathValue("o")] {
			msg(w, 404, "organization not found")
			return
		}
		names := []string{}
		for n := range s.ext.orgSecrets[r.PathValue("o")] {
			names = append(names, n)
		}
		sort.Strings(names)
		out := []map[string]any{}
		for _, n := range paginate(w, r, names, s.Max) {
			out = append(out, map[string]any{"name": n, "created_at": "2026-11-02T12:00:00Z"})
		}
		writeJSON(w, 200, out)
	})

	// ---- runners
	runnerList := func(w http.ResponseWriter, r *http.Request, keep func(fakeRunner) bool) {
		out := []map[string]any{}
		for _, rn := range s.ext.runners {
			if keep(rn) {
				out = append(out, map[string]any{"id": rn.ID, "uuid": "u" + strconv.FormatInt(rn.ID, 10), "name": rn.Name, "labels": rn.Labels,
					"status": rn.Status, "version": "v9", "ephemeral": false, "owner_id": rn.OwnerID, "repo_id": rn.RepoID})
			}
		}
		writeJSON(w, 200, paginate(w, r, out, s.Max))
	}
	h("GET "+a+"/repos/{o}/{r}/actions/runners", func(w http.ResponseWriter, r *http.Request) {
		if s.getRepo(w, r) == nil {
			return
		}
		vis := r.URL.Query().Get("visible") == "true"
		runnerList(w, r, func(rn fakeRunner) bool {
			switch rn.Scope {
			case "repo":
				return rn.Owner == r.PathValue("o") && rn.Rep == r.PathValue("r")
			case "org":
				return vis && rn.Owner == r.PathValue("o")
			}
			return vis
		})
	})
	h("GET "+a+"/orgs/{o}/actions/runners", func(w http.ResponseWriter, r *http.Request) {
		if !s.orgs[r.PathValue("o")] {
			msg(w, 404, "organization not found")
			return
		}
		vis := r.URL.Query().Get("visible") == "true"
		runnerList(w, r, func(rn fakeRunner) bool {
			switch rn.Scope {
			case "org":
				return rn.Owner == r.PathValue("o")
			case "global":
				return vis
			}
			return false
		})
	})
	h("GET "+a+"/admin/actions/runners", func(w http.ResponseWriter, r *http.Request) {
		runnerList(w, r, func(rn fakeRunner) bool { return true })
	})

	// ---- team get / patch
	teamID := func(r *http.Request) int64 { n, _ := strconv.ParseInt(r.PathValue("id"), 10, 64); return n }
	h("GET "+a+"/teams/{id}", func(w http.ResponseWriter, r *http.Request) {
		t := s.teams[teamID(r)]
		if t == nil {
			msg(w, 404, "team not found")
			return
		}
		writeJSON(w, 200, t)
	})
	h("PATCH "+a+"/teams/{id}", func(w http.ResponseWriter, r *http.Request) {
		t := s.teams[teamID(r)]
		if t == nil {
			msg(w, 404, "team not found")
			return
		}
		b := bodyOf(r)
		if str(b, "name") == "" {
			msg(w, 422, "name is required")
			return
		}
		for _, k := range []string{"name", "permission", "units", "units_map"} {
			if v, ok := b[k]; ok {
				t[k] = v
			}
		}
		writeJSON(w, 200, t)
	})

	// ---- tag protection
	key := func(r *http.Request) string { return r.PathValue("o") + "/" + r.PathValue("r") }
	h("GET "+a+"/repos/{o}/{r}/tag_protections", func(w http.ResponseWriter, r *http.Request) {
		if s.getRepo(w, r) == nil {
			return
		}
		out := s.ext.tagProt[key(r)]
		if out == nil {
			out = []map[string]any{}
		}
		writeJSON(w, 200, out)
	})
	h("POST "+a+"/repos/{o}/{r}/tag_protections", func(w http.ResponseWriter, r *http.Request) {
		if s.getRepo(w, r) == nil {
			return
		}
		b := bodyOf(r)
		pat := str(b, "name_pattern")
		if pat == "" {
			msg(w, 422, "name_pattern is required")
			return
		}
		for _, x := range s.ext.tagProt[key(r)] {
			if x["name_pattern"] == pat {
				msg(w, 422, "tag protection already exists")
				return
			}
		}
		if s.ext.tagProt == nil {
			s.ext.tagProt = map[string][]map[string]any{}
		}
		s.ext.tagSeq++
		rule := map[string]any{"id": s.ext.tagSeq, "name_pattern": pat, "whitelist_usernames": b["whitelist_usernames"], "whitelist_teams": b["whitelist_teams"],
			"created_at": "2026-11-02T12:00:00Z", "updated_at": "2026-11-02T12:00:00Z"}
		s.ext.tagProt[key(r)] = append(s.ext.tagProt[key(r)], rule)
		writeJSON(w, 201, rule)
	})
	h("PATCH "+a+"/repos/{o}/{r}/tag_protections/{id}", func(w http.ResponseWriter, r *http.Request) {
		if s.getRepo(w, r) == nil {
			return
		}
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		b := bodyOf(r)
		for _, x := range s.ext.tagProt[key(r)] {
			if x["id"] == id {
				for _, k := range []string{"name_pattern", "whitelist_usernames", "whitelist_teams"} {
					if v, ok := b[k]; ok {
						x[k] = v
					}
				}
				writeJSON(w, 200, x)
				return
			}
		}
		msg(w, 404, "tag protection not found")
	})
	h("DELETE "+a+"/repos/{o}/{r}/tag_protections/{id}", func(w http.ResponseWriter, r *http.Request) {
		if s.getRepo(w, r) == nil {
			return
		}
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		rules := s.ext.tagProt[key(r)]
		for i, x := range rules {
			if x["id"] == id {
				s.ext.tagProt[key(r)] = append(rules[:i:i], rules[i+1:]...)
				w.WriteHeader(204)
				return
			}
		}
		msg(w, 404, "tag protection not found")
	})
}
