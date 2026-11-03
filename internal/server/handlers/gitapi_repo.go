package handlers

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitprotect"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

// ---- repository document --------------------------------------------------------------------

type cloneCapsule struct {
	Command    string `json:"command"`
	InstallURL string `json:"install_url,omitempty"`
}

type cloneKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type cloneHTTPS struct {
	URL       string    `json:"url"`
	Command   string    `json:"command"`
	GCMConfig []cloneKV `json:"gcm_config"`
	GCMNote   string    `json:"gcm_note"`
}

type cloneSSH struct {
	URL     string `json:"url"`
	Command string `json:"command"`
}

type cloneOptions struct {
	Capsule cloneCapsule `json:"capsule"`
	HTTPS   cloneHTTPS   `json:"https"`
	SSH     cloneSSH     `json:"ssh"`
}

// repoDoc is the API schema Repo plus the legacy keys of GET .../git/repo (status, attempts,
// web_url, clone_url_*), so existing consumers keep working.
type repoDoc struct {
	ProvisionStatus     string        `json:"provision_status"`
	LastError           string        `json:"last_error,omitempty"`
	DefaultBranch       string        `json:"default_branch"`
	AllowedMergeStyles  []string      `json:"allowed_merge_styles"`
	DeleteBranchOnMerge bool          `json:"delete_branch_on_merge"`
	Archived            bool          `json:"archived"`
	SizeKB              int64         `json:"size_kb"`
	ForgejoURL          string        `json:"forgejo_url"`
	CloneHTTPS          string        `json:"clone_https"`
	CloneSSH            string        `json:"clone_ssh"`
	Clone               *cloneOptions `json:"clone,omitempty"`
	// legacy
	Status        string `json:"status"`
	Attempts      int    `json:"attempts"`
	WebURL        string `json:"web_url"`
	CloneURLHTTPS string `json:"clone_url_https"`
	CloneURLSSH   string `json:"clone_url_ssh"`
}

// repoURLs returns web, https and ssh URLs: the configured ones when the legacy core knows them,
// derived from the repository otherwise.
func (a *gitAPI) repoURLs(sc *gitScope, repo *gitcore.Repository) (web, https, ssh string) {
	if a.d.Legacy != nil && sc.proj != nil {
		u := a.d.Legacy.pendingURLs(sc.ctx, sc.proj)
		web, https, ssh = u.WebURL, u.CloneHTTPS, u.CloneSSH
	}
	if repo != nil {
		if web == "" {
			web = repo.HTMLURL
		}
		if https == "" && repo.HTMLURL != "" {
			https = strings.TrimRight(repo.HTMLURL, "/") + ".git"
		}
	}
	return
}

func (a *gitAPI) buildRepoDoc(sc *gitScope, status string, attempts int, lastErr string, repo *gitcore.Repository) repoDoc {
	web, https, ssh := a.repoURLs(sc, repo)
	d := repoDoc{ProvisionStatus: status, LastError: lastErr, AllowedMergeStyles: []string{}, ForgejoURL: web,
		CloneHTTPS: https, CloneSSH: ssh, Status: status, Attempts: attempts, WebURL: web, CloneURLHTTPS: https, CloneURLSSH: ssh}
	if repo != nil {
		d.DefaultBranch, d.DeleteBranchOnMerge, d.Archived, d.SizeKB = repo.DefaultBranch, repo.DeleteBranchOnPR, repo.Archived, repo.SizeKB
		if repo.AllowedMergeStyles != nil {
			d.AllowedMergeStyles = repo.AllowedMergeStyles
		}
	}
	slug := sc.ref.String()
	d.Clone = &cloneOptions{
		Capsule: cloneCapsule{Command: "capsule git clone " + slug},
		HTTPS: cloneHTTPS{URL: https, Command: "git clone " + https,
			GCMConfig: []cloneKV{{Key: "credential.useHttpPath", Value: "true"}},
			GCMNote:   "With Git Credential Manager the first clone opens your browser to sign in; otherwise use a Git Capsule access token as the password."},
		SSH: cloneSSH{URL: ssh, Command: "git clone " + ssh},
	}
	return d
}

// repoGet: GET .../git/repo
func (a *gitAPI) repoGet(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.ProjectRead)
	if !ok {
		return
	}
	status, attempts, lastErr := domain.GitCoreReady, 0, ""
	if a.d.Legacy != nil && a.d.Legacy.core != nil {
		st, err := a.d.Legacy.core.Status(r.Context(), sc.proj.ID)
		switch {
		case err == nil:
			status, attempts, lastErr = st.Status, st.Attempts, st.LastError
		case errors.Is(err, domain.ErrNotFound):
			if a.d.Git != nil {
				g, gerr := a.d.Git.Git.Get(r.Context(), sc.proj.ID)
				if gerr != nil || g.Provider != "forgejo" {
					respondError(w, http.StatusNotFound, "NOT_FOUND", "project has no repository in the core Git service")
					return
				}
			}
		default:
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load provisioning state")
			return
		}
	}
	repo, err := sc.core.GetRepo(sc.ctx, sc.ref)
	if err != nil {
		if errors.Is(err, gitcore.ErrNotFound) {
			if status == domain.GitCoreReady {
				respondError(w, http.StatusNotFound, "NOT_FOUND", "project has no repository in the core Git service")
				return
			}
			repo = nil // still provisioning: answer with the state and the URLs only
		} else {
			a.fail(w, err, false)
			return
		}
	}
	respondJSON(w, http.StatusOK, a.buildRepoDoc(sc, status, attempts, lastErr, repo))
}

// repoProvision: POST .../git/repo. Provisioning (SSRF-validated import, team sync, webhook, git
// link) is owned by the core Git service; this route adds Idempotency-Key and the Repo document.
func (a *gitAPI) repoProvision(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.ProjectOps)
	if !ok {
		return
	}
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	a.withIdempotency(w, r, sc, "repoProvision", body, func(out http.ResponseWriter) {
		var in struct {
			ImportURL     string `json:"import_url"`
			DefaultBranch string `json:"default_branch"`
		}
		if !decodeStrict(out, body, &in, true) {
			return
		}
		r2 := r.Clone(r.Context())
		r2.Body = io.NopCloser(bytes.NewReader(body))
		cw := newCapture()
		a.d.Legacy.CreateRepo(cw, r2)
		if cw.status >= 300 {
			cw.flushTo(out) // already an {error:{code,message}} document
			return
		}
		status := domain.GitCoreReady
		if cw.status == http.StatusAccepted {
			status = domain.GitCorePending
		}
		repo, _ := sc.core.GetRepo(sc.ctx, sc.ref)
		respondJSON(out, cw.status, a.buildRepoDoc(sc, status, 0, "", repo))
	})
}

type repoSettingsIn struct {
	AllowedMergeStyles  []string `json:"allowed_merge_styles"`
	Archived            *bool    `json:"archived"`
	DefaultBranch       *string  `json:"default_branch"`
	DeleteBranchOnMerge *bool    `json:"delete_branch_on_merge"`
}

// repoUpdate: PATCH .../git/repo
func (a *gitAPI) repoUpdate(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitAdmin)
	if !ok {
		return
	}
	var in repoSettingsIn
	if !a.readJSON(w, r, &in, false) {
		return
	}
	patch := gitcore.RepoPatch{DefaultBranch: in.DefaultBranch, Archived: in.Archived, DeleteBranchOnPR: in.DeleteBranchOnMerge}
	if in.DefaultBranch != nil && !gitsource.ValidBranch(*in.DefaultBranch) {
		badRequest(w, "invalid default_branch")
		return
	}
	if in.AllowedMergeStyles != nil {
		if len(in.AllowedMergeStyles) == 0 {
			badRequest(w, "allowed_merge_styles must keep at least one style")
			return
		}
		seen := map[string]bool{}
		for _, s := range in.AllowedMergeStyles {
			switch s {
			case "merge", "squash", "rebase", "fast-forward":
			default:
				badRequest(w, "allowed_merge_styles accepts merge, squash, rebase and fast-forward")
				return
			}
			if seen[s] {
				badRequest(w, "allowed_merge_styles has duplicates")
				return
			}
			seen[s] = true
		}
		patch.AllowedMergeStyles = in.AllowedMergeStyles
	}
	if patch.DefaultBranch == nil && patch.Archived == nil && patch.DeleteBranchOnPR == nil && patch.AllowedMergeStyles == nil {
		badRequest(w, "nothing to change")
		return
	}
	if in.DefaultBranch != nil { // the new default must exist
		if _, err := sc.core.GetBranch(sc.ctx, sc.ref, *in.DefaultBranch); err != nil {
			if errors.Is(err, gitcore.ErrNotFound) {
				badRequest(w, "default_branch does not exist in the repository")
				return
			}
			a.fail(w, err, false)
			return
		}
	}
	if gp := gitprotect.Shared(); gp != nil && patch.AllowedMergeStyles != nil {
		if err := gp.CheckMergeStyles(sc.ctx, sc.protectTarget(), patch.AllowedMergeStyles); err != nil {
			a.failProtect(w, err)
			return
		}
	}
	repo, err := sc.core.PatchRepo(sc.ctx, sc.ref, patch)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusOK, a.buildRepoDoc(sc, domain.GitCoreReady, 0, "", repo))
}

// ---- tree, blob, compare --------------------------------------------------------------------

// refOrDefault validates ?ref= and falls back to the default branch.
func (a *gitAPI) refOrDefault(w http.ResponseWriter, sc *gitScope, ref string) (string, *gitcore.Repository, bool) {
	ref = strings.TrimSpace(ref)
	if ref != "" {
		if !validRefName(ref) {
			badRequest(w, "invalid ref")
			return "", nil, false
		}
		return ref, nil, true
	}
	def, repo, err := a.defaultBranch(sc)
	if err != nil {
		a.fail(w, err, false)
		return "", nil, false
	}
	return def, repo, true
}

// repoTree: GET .../git/tree?ref=&path=
func (a *gitAPI) repoTree(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitRead)
	if !ok {
		return
	}
	dir, ok := cleanPath(r.URL.Query().Get("path"))
	if !ok {
		badRequest(w, "invalid path")
		return
	}
	pg, ok := pageParams(w, r)
	if !ok {
		return
	}
	ref, repo, ok := a.refOrDefault(w, sc, r.URL.Query().Get("ref"))
	if !ok {
		return
	}
	if repo != nil && repo.Empty {
		respondJSON(w, http.StatusOK, newList([]gitcore.TreeEntry{}, ""))
		return
	}
	l, err := sc.core.ListTree(sc.ctx, sc.ref, ref, dir, pg)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusOK, newList(l.Items, l.NextCursor))
}

// repoBlob: GET .../git/blob?ref=&path=
func (a *gitAPI) repoBlob(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitRead)
	if !ok {
		return
	}
	p, ok := cleanPath(r.URL.Query().Get("path"))
	if !ok || p == "" {
		badRequest(w, "path is required and must be a file path inside the repository")
		return
	}
	ref, _, ok := a.refOrDefault(w, sc, r.URL.Query().Get("ref"))
	if !ok {
		return
	}
	b, err := sc.core.GetFile(sc.ctx, sc.ref, ref, p)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	// The viewer never renders repository HTML/SVG: tell browsers that too.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	respondJSON(w, http.StatusOK, gitapi.ToBlob(b, p))
}

type compareOut struct {
	AheadBy   int                `json:"ahead_by"`
	BehindBy  int                `json:"behind_by"`
	Commits   []gitcore.Commit   `json:"commits"`
	Files     []gitcore.FileDiff `json:"files"`
	Truncated bool               `json:"truncated"`
}

// repoCompare: GET .../git/compare?base=&head=
func (a *gitAPI) repoCompare(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitRead)
	if !ok {
		return
	}
	q := r.URL.Query()
	head := strings.TrimSpace(q.Get("head"))
	if head == "" || !validRefName(head) {
		badRequest(w, "head is required and must be a valid ref")
		return
	}
	base, _, ok := a.refOrDefault(w, sc, q.Get("base"))
	if !ok {
		return
	}
	cmp, err := sc.core.Compare(sc.ctx, sc.ref, base, head)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	out := compareOut{AheadBy: cmp.AheadBy, BehindBy: cmp.BehindBy, Commits: cmp.Commits, Files: cmp.Files, Truncated: cmp.Truncated}
	if out.BehindBy == 0 { // gitcore does not know it: one reverse compare
		if rev, err := sc.core.Compare(sc.ctx, sc.ref, head, base); err == nil {
			out.BehindBy = rev.AheadBy
		}
	}
	if out.Commits == nil {
		out.Commits = []gitcore.Commit{}
	}
	if out.Files == nil {
		out.Files = []gitcore.FileDiff{}
	}
	respondJSON(w, http.StatusOK, out)
}
