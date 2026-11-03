package fake

import (
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func (s *Server) route(w http.ResponseWriter, r *http.Request, body string, max int) {
	r.Body = io.NopCloser(strings.NewReader(body))
	s.mux.ServeHTTP(w, r)
}

func bodyOf(r *http.Request) map[string]any {
	b, _ := io.ReadAll(r.Body)
	return decode(string(b))
}

func str(m map[string]any, k string) string { v, _ := m[k].(string); return v }

func (s *Server) buildMux() *http.ServeMux {
	m := http.NewServeMux()
	const a = "/api/v1"
	h := func(p string, f func(http.ResponseWriter, *http.Request)) { m.HandleFunc(p, f) }

	h("GET "+a+"/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"version": "15.0.11-fake"})
	})

	// ---- orgs, users, repos
	h("GET "+a+"/orgs/{o}", func(w http.ResponseWriter, r *http.Request) {
		if !s.orgs[r.PathValue("o")] {
			msg(w, 404, "org not found")
			return
		}
		writeJSON(w, 200, map[string]any{"username": r.PathValue("o")})
	})
	h("POST "+a+"/orgs", func(w http.ResponseWriter, r *http.Request) {
		b := bodyOf(r)
		n := str(b, "username")
		if s.orgs[n] {
			msg(w, 422, "org already exists")
			return
		}
		s.orgs[n] = true
		writeJSON(w, 201, map[string]any{"username": n})
	})
	h("GET "+a+"/users/{u}", func(w http.ResponseWriter, r *http.Request) {
		if !s.users[r.PathValue("u")] {
			msg(w, 404, "user does not exist")
			return
		}
		writeJSON(w, 200, userObj(r.PathValue("u")))
	})
	repoObj := func(rp *repo) map[string]any {
		return map[string]any{"name": rp.Name, "owner": userObj(rp.Owner), "default_branch": rp.Default, "private": rp.Private, "empty": len(rp.Branches) == 0,
			"html_url": s.URL + "/" + rp.Owner + "/" + rp.Name, "size": 12, "allow_merge_commits": true, "allow_squash_merge": true, "allow_rebase": false}
	}
	h("GET "+a+"/repos/{o}/{r}", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			writeJSON(w, 200, repoObj(rp))
		}
	})
	h("PATCH "+a+"/repos/{o}/{r}", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			b := bodyOf(r)
			if d := str(b, "default_branch"); d != "" {
				rp.Default = d
			}
			writeJSON(w, 200, repoObj(rp))
		}
	})
	h("POST "+a+"/orgs/{o}/repos", func(w http.ResponseWriter, r *http.Request) {
		o := r.PathValue("o")
		if !s.orgs[o] {
			msg(w, 404, "org not found")
			return
		}
		b := bodyOf(r)
		n := str(b, "name")
		if s.repos[o+"/"+n] != nil {
			msg(w, 409, "repo exists")
			return
		}
		priv, _ := b["private"].(bool)
		s.newRepo(o, n, priv)
		writeJSON(w, 201, repoObj(s.repos[o+"/"+n]))
	})
	h("POST "+a+"/repos/migrate", func(w http.ResponseWriter, r *http.Request) {
		b := bodyOf(r)
		o, n := str(b, "repo_owner"), str(b, "repo_name")
		if s.repos[o+"/"+n] != nil {
			msg(w, 409, "repo exists")
			return
		}
		s.orgs[o] = true
		s.newRepo(o, n, true)
		writeJSON(w, 201, repoObj(s.repos[o+"/"+n]))
	})

	// ---- branches, tags
	h("GET "+a+"/repos/{o}/{r}/branches", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		var names []string
		for n := range rp.Branches {
			names = append(names, n)
		}
		sort.Strings(names)
		out := []map[string]any{}
		for _, n := range paginate(w, r, names, s.Max) {
			out = append(out, s.branchObj(rp, n))
		}
		writeJSON(w, 200, out)
	})
	h("GET "+a+"/repos/{o}/{r}/branches/{b...}", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		if _, ok := rp.Branches[r.PathValue("b")]; !ok {
			msg(w, 404, "branch not found")
			return
		}
		writeJSON(w, 200, s.branchObj(rp, r.PathValue("b")))
	})
	h("POST "+a+"/repos/{o}/{r}/branches", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		b := bodyOf(r)
		n, from := str(b, "new_branch_name"), str(b, "old_ref_name")
		if _, ok := rp.Branches[n]; ok {
			msg(w, 409, "branch already exists")
			return
		}
		src, ok := rp.Branches[from]
		if !ok {
			msg(w, 404, "source not found")
			return
		}
		rp.Branches[n] = src
		writeJSON(w, 201, s.branchObj(rp, n))
	})
	h("DELETE "+a+"/repos/{o}/{r}/branches/{b...}", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		n := r.PathValue("b")
		if _, ok := rp.Branches[n]; !ok {
			msg(w, 404, "branch not found")
			return
		}
		if _, prot := rp.Prot[n]; prot {
			msg(w, 403, "branch is protected")
			return
		}
		delete(rp.Branches, n)
		w.WriteHeader(204)
	})
	h("GET "+a+"/repos/{o}/{r}/tags", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		var names []string
		for n := range rp.Tags {
			names = append(names, n)
		}
		sort.Strings(names)
		out := []map[string]any{}
		for _, n := range paginate(w, r, names, s.Max) {
			out = append(out, map[string]any{"name": n, "id": "t" + rp.Tags[n], "message": "", "commit": map[string]any{"sha": rp.Tags[n], "created": "2026-11-02T12:00:00Z"}})
		}
		writeJSON(w, 200, out)
	})
	h("POST "+a+"/repos/{o}/{r}/tags", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		b := bodyOf(r)
		n, tgt := str(b, "tag_name"), str(b, "target")
		sh, ok := rp.Branches[tgt]
		if !ok {
			sh = tgt
		}
		if _, ok := rp.Commits[sh]; !ok {
			msg(w, 404, "target not found")
			return
		}
		if _, ex := rp.Tags[n]; ex {
			msg(w, 409, "tag exists")
			return
		}
		rp.Tags[n] = sh
		writeJSON(w, 201, map[string]any{"name": n, "id": "t" + sh, "commit": map[string]any{"sha": sh}})
	})
	h("DELETE "+a+"/repos/{o}/{r}/tags/{t...}", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		if _, ok := rp.Tags[r.PathValue("t")]; !ok {
			msg(w, 404, "tag not found")
			return
		}
		delete(rp.Tags, r.PathValue("t"))
		w.WriteHeader(204)
	})

	// ---- commits, contents, blobs, compare
	resolve := func(rp *repo, ref string) string {
		if sh, ok := rp.Branches[ref]; ok {
			return sh
		}
		if sh, ok := rp.Tags[ref]; ok {
			return sh
		}
		if _, ok := rp.Commits[ref]; ok {
			return ref
		}
		return ""
	}
	h("GET "+a+"/repos/{o}/{r}/commits", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		ref := r.URL.Query().Get("sha")
		if ref == "" {
			ref = rp.Default
		}
		sh := resolve(rp, ref)
		if sh == "" {
			msg(w, 404, "ref not found")
			return
		}
		var chain []*commit
		for sh != "" {
			c := rp.Commits[sh]
			chain = append(chain, c)
			sh = ""
			if len(c.Parents) > 0 {
				sh = c.Parents[0]
			}
		}
		out := []map[string]any{}
		for _, c := range paginate(w, r, chain, s.Max) {
			out = append(out, s.commitObj(rp, c, false))
		}
		writeJSON(w, 200, out)
	})
	h("GET "+a+"/repos/{o}/{r}/git/commits/{sha}", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		name := r.PathValue("sha")
		diff := strings.HasSuffix(name, ".diff")
		name = strings.TrimSuffix(name, ".diff")
		c := rp.Commits[name]
		if c == nil {
			msg(w, 404, "commit not found")
			return
		}
		if diff {
			var prev map[string]string
			if len(c.Parents) > 0 {
				prev = rp.Commits[c.Parents[0]].Files
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, unified(prev, c.Files))
			return
		}
		writeJSON(w, 200, s.commitObj(rp, c, true))
	})
	contents := func(w http.ResponseWriter, r *http.Request, path string) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		ref := r.URL.Query().Get("ref")
		if ref == "" {
			ref = rp.Default
		}
		sh := resolve(rp, ref)
		if sh == "" {
			msg(w, 404, "ref not found")
			return
		}
		files := rp.Commits[sh].Files
		path = strings.Trim(path, "/")
		if content, ok := files[path]; ok && path != "" {
			writeJSON(w, 200, map[string]any{"name": path[strings.LastIndex(path, "/")+1:], "path": path, "type": "file", "size": len(content),
				"sha": sha(content), "encoding": "base64", "content": b64(content)})
			return
		}
		prefix := path
		if prefix != "" {
			prefix += "/"
		}
		seen := map[string]map[string]any{}
		for p, c := range files {
			if !strings.HasPrefix(p, prefix) {
				continue
			}
			rest := strings.TrimPrefix(p, prefix)
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				seen[rest[:i]] = map[string]any{"name": rest[:i], "path": prefix + rest[:i], "type": "dir", "size": 0, "sha": sha(prefix + rest[:i])}
			} else {
				seen[rest] = map[string]any{"name": rest, "path": p, "type": "file", "size": len(c), "sha": sha(c)}
			}
		}
		if len(seen) == 0 {
			msg(w, 404, "path not found")
			return
		}
		out := []map[string]any{}
		for _, v := range seen {
			out = append(out, v)
		}
		writeJSON(w, 200, out)
	}
	h("GET "+a+"/repos/{o}/{r}/contents", func(w http.ResponseWriter, r *http.Request) { contents(w, r, "") })
	h("GET "+a+"/repos/{o}/{r}/contents/{p...}", func(w http.ResponseWriter, r *http.Request) { contents(w, r, r.PathValue("p")) })
	h("GET "+a+"/repos/{o}/{r}/git/blobs/{sha}", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		for _, c := range rp.Commits {
			for _, content := range c.Files {
				if sha(content) == r.PathValue("sha") {
					writeJSON(w, 200, map[string]any{"sha": r.PathValue("sha"), "size": len(content), "encoding": "base64", "content": b64(content)})
					return
				}
			}
		}
		msg(w, 404, "blob not found")
	})
	h("GET "+a+"/repos/{o}/{r}/compare/{bh}", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		parts := strings.SplitN(r.PathValue("bh"), "...", 2)
		if len(parts) != 2 {
			msg(w, 404, "bad basehead")
			return
		}
		b, hd := resolve(rp, parts[0]), resolve(rp, parts[1])
		if b == "" || hd == "" {
			msg(w, 404, "ref not found")
			return
		}
		var cs []map[string]any
		for sh := hd; sh != "" && sh != b; {
			c := rp.Commits[sh]
			cs = append([]map[string]any{s.commitObj(rp, c, false)}, cs...)
			sh = ""
			if len(c.Parents) > 0 {
				sh = c.Parents[0]
			}
		}
		fs := []map[string]any{}
		for _, f := range rp.Commits[hd].Changed {
			fs = append(fs, map[string]any{"filename": f, "status": "modified"})
		}
		writeJSON(w, 200, map[string]any{"total_commits": len(cs), "commits": cs, "files": fs})
	})

	// ---- pulls
	findPull := func(w http.ResponseWriter, r *http.Request) (*repo, *pull) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return nil, nil
		}
		n, _ := strconv.Atoi(strings.TrimSuffix(r.PathValue("n"), ".diff"))
		if n < 1 || n > len(rp.Pulls) {
			msg(w, 404, "pull request not found")
			return nil, nil
		}
		return rp, rp.Pulls[n-1]
	}
	h("GET "+a+"/repos/{o}/{r}/pulls", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		st := r.URL.Query().Get("state")
		var ps []*pull
		for _, p := range rp.Pulls {
			if st == "all" || (st == "closed" && p.State == "closed") || ((st == "open" || st == "") && p.State == "open") {
				ps = append(ps, p)
			}
		}
		out := []map[string]any{}
		for _, p := range paginate(w, r, ps, s.Max) {
			out = append(out, s.pullObj(rp, p))
		}
		writeJSON(w, 200, out)
	})
	h("POST "+a+"/repos/{o}/{r}/pulls", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		b := bodyOf(r)
		if _, ok := rp.Branches[str(b, "head")]; !ok {
			msg(w, 404, "head branch not found")
			return
		}
		p := &pull{N: len(rp.Pulls) + 1, Title: str(b, "title"), Body: str(b, "body"), Head: str(b, "head"), Base: str(b, "base"),
			HeadSHA: rp.Branches[str(b, "head")], State: "open", Author: ifThen(r.Header.Get("Sudo") != "", r.Header.Get("Sudo"), "capsule-bot")}
		rp.Pulls = append(rp.Pulls, p)
		writeJSON(w, 201, s.pullObj(rp, p))
	})
	h("GET "+a+"/repos/{o}/{r}/pulls/{n}", func(w http.ResponseWriter, r *http.Request) {
		rp, p := findPull(w, r)
		if p == nil {
			return
		}
		if strings.HasSuffix(r.PathValue("n"), ".diff") {
			var prev map[string]string
			if bs := rp.Branches[p.Base]; bs != "" {
				prev = rp.Commits[bs].Files
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, unified(prev, rp.Commits[p.HeadSHA].Files))
			return
		}
		writeJSON(w, 200, s.pullObj(rp, p))
	})
	h("PATCH "+a+"/repos/{o}/{r}/pulls/{n}", func(w http.ResponseWriter, r *http.Request) {
		rp, p := findPull(w, r)
		if p == nil {
			return
		}
		b := bodyOf(r)
		if v := str(b, "title"); v != "" {
			p.Title = v
		}
		if v, ok := b["body"].(string); ok {
			p.Body = v
		}
		if v := str(b, "state"); v != "" {
			p.State = v
		}
		writeJSON(w, 200, s.pullObj(rp, p))
	})
	h("GET "+a+"/repos/{o}/{r}/pulls/{n}/files", func(w http.ResponseWriter, r *http.Request) {
		rp, p := findPull(w, r)
		if p == nil {
			return
		}
		out := []map[string]any{}
		for _, f := range rp.Commits[p.HeadSHA].Changed {
			out = append(out, map[string]any{"filename": f, "status": "modified", "additions": 1, "deletions": 1})
		}
		writeJSON(w, 200, out)
	})
	h("GET "+a+"/repos/{o}/{r}/pulls/{n}/commits", func(w http.ResponseWriter, r *http.Request) {
		rp, p := findPull(w, r)
		if p == nil {
			return
		}
		out := []map[string]any{s.commitObj(rp, rp.Commits[p.HeadSHA], false)}
		writeJSON(w, 200, out)
	})
	h("POST "+a+"/repos/{o}/{r}/pulls/{n}/update", func(w http.ResponseWriter, r *http.Request) {
		if _, p := findPull(w, r); p != nil {
			w.WriteHeader(200)
		}
	})
	h("POST "+a+"/repos/{o}/{r}/pulls/{n}/requested_reviewers", func(w http.ResponseWriter, r *http.Request) {
		_, p := findPull(w, r)
		if p == nil {
			return
		}
		b := bodyOf(r)
		if us, ok := b["reviewers"].([]any); ok {
			for _, u := range us {
				name, _ := u.(string)
				if !s.users[name] {
					msg(w, 422, "reviewer does not exist")
					return
				}
				p.Reviewers = append(p.Reviewers, name)
			}
		}
		writeJSON(w, 201, []any{})
	})
	h("GET "+a+"/repos/{o}/{r}/pulls/{n}/reviews", func(w http.ResponseWriter, r *http.Request) {
		_, p := findPull(w, r)
		if p == nil {
			return
		}
		writeJSON(w, 200, paginate(w, r, append([]map[string]any{}, p.Reviews...), s.Max))
	})
	h("POST "+a+"/repos/{o}/{r}/pulls/{n}/reviews", func(w http.ResponseWriter, r *http.Request) {
		_, p := findPull(w, r)
		if p == nil {
			return
		}
		b := bodyOf(r)
		who := ifThen(r.Header.Get("Sudo") != "", r.Header.Get("Sudo"), "capsule-bot")
		rv := map[string]any{"id": len(p.Reviews) + 1, "state": str(b, "event"), "body": str(b, "body"), "user": userObj(who),
			"commit_id": p.HeadSHA, "submitted_at": "2026-11-02T12:10:00Z", "official": true}
		if cs, ok := b["comments"].([]any); ok {
			rv["comments_count"] = len(cs)
		}
		p.Reviews = append(p.Reviews, rv)
		writeJSON(w, 200, rv)
	})
	h("GET "+a+"/repos/{o}/{r}/issues/{n}/comments", func(w http.ResponseWriter, r *http.Request) {
		_, p := findPull(w, r)
		if p == nil {
			return
		}
		writeJSON(w, 200, paginate(w, r, append([]map[string]any{}, p.Comments...), s.Max))
	})
	h("POST "+a+"/repos/{o}/{r}/issues/{n}/comments", func(w http.ResponseWriter, r *http.Request) {
		_, p := findPull(w, r)
		if p == nil {
			return
		}
		b := bodyOf(r)
		who := ifThen(r.Header.Get("Sudo") != "", r.Header.Get("Sudo"), "capsule-bot")
		c := map[string]any{"id": len(p.Comments) + 1, "body": str(b, "body"), "user": userObj(who), "created_at": "2026-11-02T12:11:00Z", "updated_at": "2026-11-02T12:11:00Z"}
		p.Comments = append(p.Comments, c)
		writeJSON(w, 201, c)
	})
	h("POST "+a+"/repos/{o}/{r}/pulls/{n}/merge", func(w http.ResponseWriter, r *http.Request) {
		rp, p := findPull(w, r)
		if p == nil {
			return
		}
		b := bodyOf(r)
		if p.State != "open" {
			msg(w, 405, "pull request is not open")
			return
		}
		if hc := str(b, "head_commit_id"); hc != "" && hc != p.HeadSHA {
			msg(w, 409, "head commit changed")
			return
		}
		if wc, _ := b["merge_when_checks_succeed"].(bool); wc {
			p.AutoMerge = true
			w.WriteHeader(200)
			return
		}
		if pr, ok := rp.Prot[p.Base]; ok {
			if n, _ := pr["required_approvals"].(float64); n > 0 {
				approved := 0
				for _, rv := range p.Reviews {
					if rv["state"] == "APPROVED" {
						approved++
					}
				}
				if approved < int(n) {
					msg(w, 405, "Does not have enough approvals yet")
					return
				}
			}
		}
		p.Merged, p.State = true, "closed"
		p.MergeSHA = s.commit(rp, p.Base, "Merge #"+strconv.Itoa(p.N), "alice", rp.Commits[p.HeadSHA].Files)
		w.WriteHeader(200)
	})
	h("DELETE "+a+"/repos/{o}/{r}/pulls/{n}/merge", func(w http.ResponseWriter, r *http.Request) {
		if _, p := findPull(w, r); p != nil {
			p.AutoMerge = false
			w.WriteHeader(204)
		}
	})

	// ---- statuses
	h("GET "+a+"/repos/{o}/{r}/commits/{ref...}", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		ref := strings.TrimSuffix(r.PathValue("ref"), "/status")
		sh := resolve(rp, ref)
		if sh == "" {
			msg(w, 404, "ref not found")
			return
		}
		sts := rp.Statuses[sh]
		state := "pending"
		if len(sts) > 0 {
			state = "success"
			for _, st := range sts {
				if st["status"] == "failure" || st["status"] == "error" {
					state = "failure"
				}
			}
		}
		writeJSON(w, 200, map[string]any{"sha": sh, "state": state, "statuses": sts, "total_count": len(sts)})
	})
	h("POST "+a+"/repos/{o}/{r}/statuses/{sha}", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		sh := r.PathValue("sha")
		if _, ok := rp.Commits[sh]; !ok {
			msg(w, 404, "commit not found")
			return
		}
		b := bodyOf(r)
		st := map[string]any{"context": str(b, "context"), "status": str(b, "state"), "target_url": str(b, "target_url"), "description": str(b, "description"), "updated_at": "2026-11-02T12:12:00Z"}
		rp.Statuses[sh] = append(rp.Statuses[sh], st)
		writeJSON(w, 201, st)
	})

	// ---- branch protections
	h("GET "+a+"/repos/{o}/{r}/branch_protections", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		out := []map[string]any{}
		var names []string
		for n := range rp.Prot {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, rp.Prot[n])
		}
		writeJSON(w, 200, out)
	})
	h("POST "+a+"/repos/{o}/{r}/branch_protections", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		b := bodyOf(r)
		n := str(b, "rule_name")
		if n == "" {
			msg(w, 422, "rule_name is required")
			return
		}
		if rp.Prot[n] != nil {
			msg(w, 403, "Branch protection already exist")
			return
		}
		b["created_at"], b["updated_at"] = "2026-11-02T12:00:00Z", "2026-11-02T12:00:00Z"
		rp.Prot[n] = b
		writeJSON(w, 201, b)
	})
	h("GET "+a+"/repos/{o}/{r}/branch_protections/{n}", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		if p := rp.Prot[r.PathValue("n")]; p != nil {
			writeJSON(w, 200, p)
			return
		}
		msg(w, 404, "branch protection not found")
	})
	h("PATCH "+a+"/repos/{o}/{r}/branch_protections/{n}", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		p := rp.Prot[r.PathValue("n")]
		if p == nil {
			msg(w, 404, "branch protection not found")
			return
		}
		for k, v := range bodyOf(r) {
			p[k] = v
		}
		p["updated_at"] = "2026-11-02T12:30:00Z"
		writeJSON(w, 200, p)
	})
	h("DELETE "+a+"/repos/{o}/{r}/branch_protections/{n}", func(w http.ResponseWriter, r *http.Request) {
		rp := s.getRepo(w, r)
		if rp == nil {
			return
		}
		if rp.Prot[r.PathValue("n")] == nil {
			msg(w, 404, "branch protection not found")
			return
		}
		delete(rp.Prot, r.PathValue("n"))
		w.WriteHeader(204)
	})

	// ---- teams
	h("GET "+a+"/orgs/{o}/teams/search", func(w http.ResponseWriter, r *http.Request) {
		q := strings.ToLower(r.URL.Query().Get("q"))
		out := []map[string]any{}
		for _, t := range s.teams {
			if t["org"] == r.PathValue("o") && strings.Contains(strings.ToLower(t["name"].(string)), q) {
				out = append(out, t)
			}
		}
		writeJSON(w, 200, map[string]any{"ok": true, "data": out})
	})
	h("POST "+a+"/orgs/{o}/teams", func(w http.ResponseWriter, r *http.Request) {
		b := bodyOf(r)
		id := int64(len(s.teams) + 1)
		t := map[string]any{"id": id, "name": str(b, "name"), "permission": str(b, "permission"), "org": r.PathValue("o")}
		s.teams[id], s.tmem[id] = t, map[string]bool{}
		writeJSON(w, 201, t)
	})
	teamID := func(r *http.Request) int64 { n, _ := strconv.ParseInt(r.PathValue("id"), 10, 64); return n }
	h("PUT "+a+"/teams/{id}/repos/{o}/{r}", func(w http.ResponseWriter, r *http.Request) {
		if s.teams[teamID(r)] == nil {
			msg(w, 404, "team not found")
			return
		}
		if rp := s.getRepo(w, r); rp != nil {
			rp.Teams[teamID(r)] = true
			w.WriteHeader(204)
		}
	})
	h("GET "+a+"/teams/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		if s.teams[teamID(r)] == nil {
			msg(w, 404, "team not found")
			return
		}
		var names []string
		for u := range s.tmem[teamID(r)] {
			names = append(names, u)
		}
		sort.Strings(names)
		out := []map[string]any{}
		for _, n := range paginate(w, r, names, s.Max) {
			out = append(out, userObj(n))
		}
		writeJSON(w, 200, out)
	})
	h("PUT "+a+"/teams/{id}/members/{u}", func(w http.ResponseWriter, r *http.Request) {
		if s.teams[teamID(r)] == nil || !s.users[r.PathValue("u")] {
			msg(w, 404, "not found")
			return
		}
		s.tmem[teamID(r)][r.PathValue("u")] = true
		w.WriteHeader(204)
	})
	h("DELETE "+a+"/teams/{id}/members/{u}", func(w http.ResponseWriter, r *http.Request) {
		if s.teams[teamID(r)] == nil || !s.tmem[teamID(r)][r.PathValue("u")] {
			msg(w, 404, "not a member")
			return
		}
		delete(s.tmem[teamID(r)], r.PathValue("u"))
		w.WriteHeader(204)
	})

	// ---- hooks, keys, mirrors
	h("GET "+a+"/repos/{o}/{r}/hooks", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			writeJSON(w, 200, paginate(w, r, append([]map[string]any{}, rp.Hooks...), s.Max))
		}
	})
	h("POST "+a+"/repos/{o}/{r}/hooks", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			b := bodyOf(r)
			b["id"] = len(rp.Hooks) + 1
			rp.Hooks = append(rp.Hooks, b)
			writeJSON(w, 201, b)
		}
	})
	h("PATCH "+a+"/repos/{o}/{r}/hooks/{id}", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			id, _ := strconv.Atoi(r.PathValue("id"))
			for _, hk := range rp.Hooks {
				if int(hk["id"].(int)) == id {
					for k, v := range bodyOf(r) {
						hk[k] = v
					}
					writeJSON(w, 200, hk)
					return
				}
			}
			msg(w, 404, "hook not found")
		}
	})
	h("DELETE "+a+"/repos/{o}/{r}/hooks/{id}", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			id, _ := strconv.Atoi(r.PathValue("id"))
			for i, hk := range rp.Hooks {
				if hk["id"].(int) == id {
					rp.Hooks = append(rp.Hooks[:i], rp.Hooks[i+1:]...)
					w.WriteHeader(204)
					return
				}
			}
			msg(w, 404, "hook not found")
		}
	})
	h("GET "+a+"/user/keys", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, paginate(w, r, append([]map[string]any{}, s.keys[r.Header.Get("Sudo")]...), s.Max))
	})
	h("POST "+a+"/user/keys", func(w http.ResponseWriter, r *http.Request) {
		u := r.Header.Get("Sudo")
		b := bodyOf(r)
		b["id"], b["fingerprint"], b["created_at"] = len(s.keys[u])+1, "SHA256:"+sha(str(b, "key"))[:20], "2026-11-02T12:00:00Z"
		s.keys[u] = append(s.keys[u], b)
		writeJSON(w, 201, b)
	})
	h("DELETE "+a+"/user/keys/{id}", func(w http.ResponseWriter, r *http.Request) {
		u := r.Header.Get("Sudo")
		id, _ := strconv.Atoi(r.PathValue("id"))
		for i, k := range s.keys[u] {
			if k["id"].(int) == id {
				s.keys[u] = append(s.keys[u][:i], s.keys[u][i+1:]...)
				w.WriteHeader(204)
				return
			}
		}
		msg(w, 404, "key not found")
	})
	h("GET "+a+"/repos/{o}/{r}/push_mirrors", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			writeJSON(w, 200, paginate(w, r, append([]map[string]any{}, rp.Mirrors...), s.Max))
		}
	})
	h("POST "+a+"/repos/{o}/{r}/push_mirrors", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			b := bodyOf(r)
			delete(b, "remote_password")
			b["remote_name"] = "remote_mirror_" + strconv.Itoa(len(rp.Mirrors)+1)
			rp.Mirrors = append(rp.Mirrors, b)
			writeJSON(w, 200, b)
		}
	})
	h("DELETE "+a+"/repos/{o}/{r}/push_mirrors/{n}", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			for i, m := range rp.Mirrors {
				if m["remote_name"] == r.PathValue("n") {
					rp.Mirrors = append(rp.Mirrors[:i], rp.Mirrors[i+1:]...)
					w.WriteHeader(204)
					return
				}
			}
			msg(w, 404, "mirror not found")
		}
	})
	h("POST "+a+"/repos/{o}/{r}/push_mirrors-sync", func(w http.ResponseWriter, r *http.Request) {
		if s.getRepo(w, r) != nil {
			w.WriteHeader(200)
		}
	})

	// ---- actions
	h("GET "+a+"/repos/{o}/{r}/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			rs := []map[string]any{}
			for _, run := range rp.Runs {
				if st := r.URL.Query().Get("status"); st == "" || run["status"] == st {
					rs = append(rs, run)
				}
			}
			writeJSON(w, 200, map[string]any{"total_count": len(rs), "workflow_runs": paginate(w, r, rs, s.Max)})
		}
	})
	h("GET "+a+"/repos/{o}/{r}/actions/runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			id, _ := strconv.Atoi(r.PathValue("id"))
			if id < 1 || id > len(rp.Runs) {
				msg(w, 404, "run not found")
				return
			}
			writeJSON(w, 200, rp.Runs[id-1])
		}
	})
	h("GET "+a+"/repos/{o}/{r}/actions/runs/{id}/jobs", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
			js, ok := rp.Jobs[id]
			if !ok {
				msg(w, 404, "run not found")
				return
			}
			writeJSON(w, 200, js)
		}
	})
	h("GET "+a+"/repos/{o}/{r}/actions/jobs/{id}/logs", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
			l, ok := rp.Logs[id]
			if !ok {
				msg(w, 404, "job not found")
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, l)
		}
	})
	h("POST "+a+"/repos/{o}/{r}/actions/runs/{id}/cancel", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			id, _ := strconv.Atoi(r.PathValue("id"))
			if id < 1 || id > len(rp.Runs) {
				msg(w, 404, "run not found")
				return
			}
			rp.Runs[id-1]["status"] = "cancelled"
			w.WriteHeader(200)
		}
	})
	h("POST "+a+"/repos/{o}/{r}/actions/workflows/{wf}/dispatches", func(w http.ResponseWriter, r *http.Request) {
		if rp := s.getRepo(w, r); rp != nil {
			b := bodyOf(r)
			if ri, _ := b["return_run_info"].(bool); ri {
				id := int64(len(rp.Runs) + 1)
				rp.Runs = append(rp.Runs, map[string]any{"id": id, "index_in_repo": id, "workflow_id": r.PathValue("wf"), "title": "dispatch", "event": "workflow_dispatch",
					"prettyref": str(b, "ref"), "commit_sha": rp.Branches[str(b, "ref")], "status": "waiting", "need_approval": false,
					"trigger_user": map[string]any{"login": "alice"}, "started": "2026-11-02T12:00:00Z", "stopped": "2026-11-02T12:00:00Z", "html_url": s.URL + "/x"})
				writeJSON(w, 201, map[string]any{"id": id, "run_number": id, "jobs": []string{"build"}})
				return
			}
			w.WriteHeader(204)
		}
	})
	vars := func(w http.ResponseWriter, r *http.Request) map[string]string {
		if r.PathValue("r") == "" {
			if s.ovars[r.PathValue("o")] == nil {
				s.ovars[r.PathValue("o")] = map[string]string{}
			}
			return s.ovars[r.PathValue("o")]
		}
		if rp := s.getRepo(w, r); rp != nil {
			return rp.Vars
		}
		return nil
	}
	for _, scope := range []string{"/repos/{o}/{r}", "/orgs/{o}"} {
		h("GET "+a+scope+"/actions/variables", func(w http.ResponseWriter, r *http.Request) {
			v := vars(w, r)
			if v == nil {
				return
			}
			out := []map[string]any{}
			for k, val := range v {
				out = append(out, map[string]any{"name": k, "data": val})
			}
			writeJSON(w, 200, out)
		})
		h("PUT "+a+scope+"/actions/variables/{n}", func(w http.ResponseWriter, r *http.Request) {
			v := vars(w, r)
			if v == nil {
				return
			}
			if _, ok := v[r.PathValue("n")]; !ok {
				msg(w, 404, "variable not found")
				return
			}
			v[r.PathValue("n")] = str(bodyOf(r), "value")
			w.WriteHeader(204)
		})
		h("POST "+a+scope+"/actions/variables/{n}", func(w http.ResponseWriter, r *http.Request) {
			v := vars(w, r)
			if v == nil {
				return
			}
			v[r.PathValue("n")] = str(bodyOf(r), "value")
			w.WriteHeader(201)
		})
		h("DELETE "+a+scope+"/actions/variables/{n}", func(w http.ResponseWriter, r *http.Request) {
			v := vars(w, r)
			if v == nil {
				return
			}
			if _, ok := v[r.PathValue("n")]; !ok {
				msg(w, 404, "variable not found")
				return
			}
			delete(v, r.PathValue("n"))
			w.WriteHeader(204)
		})
		h("PUT "+a+scope+"/actions/secrets/{n}", func(w http.ResponseWriter, r *http.Request) {
			if r.PathValue("r") != "" {
				if rp := s.getRepo(w, r); rp != nil {
					rp.Secrets[r.PathValue("n")] = str(bodyOf(r), "data")
					w.WriteHeader(201)
				}
				return
			}
			s.ext.putOrgSecret(r.PathValue("o"), r.PathValue("n"))
			w.WriteHeader(201)
		})
		h("DELETE "+a+scope+"/actions/secrets/{n}", func(w http.ResponseWriter, r *http.Request) {
			if r.PathValue("r") != "" {
				if rp := s.getRepo(w, r); rp != nil {
					if _, ok := rp.Secrets[r.PathValue("n")]; !ok {
						msg(w, 404, "secret not found")
						return
					}
					delete(rp.Secrets, r.PathValue("n"))
					w.WriteHeader(204)
				}
				return
			}
			w.WriteHeader(204)
		})
	}
	s.extRoutes(h, a)
	return m
}
