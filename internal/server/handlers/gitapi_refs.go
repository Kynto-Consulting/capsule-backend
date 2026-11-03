package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

// ---- branches -------------------------------------------------------------------------------

// branchesList: GET .../git/branches (cursor pagination; legacy envelope keys kept).
func (a *gitAPI) branchesList(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scopeAuth(w, r, authz.GitRead)
	if !ok {
		return
	}
	if a.legacyProvider(sc) {
		a.d.Legacy.Branches(w, r)
		return
	}
	if !sc.core.Enabled() {
		respondError(w, http.StatusServiceUnavailable, "GIT_NOT_READY", "the Git service is not configured on this server")
		return
	}
	pg, ok := pageParams(w, r)
	if !ok {
		return
	}
	l, err := sc.core.ListBranches(sc.ctx, sc.ref, pg)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	items := make([]gitapi.BranchOut, 0, len(l.Items))
	for _, b := range l.Items {
		items = append(items, gitapi.ToBranch(b))
	}
	respondJSON(w, http.StatusOK, newLegacyList(items, l.NextCursor))
}

type branchCreateIn struct {
	Name string `json:"name"`
	From string `json:"from"`
}

// branchCreate: POST .../git/branches
func (a *gitAPI) branchCreate(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitWrite)
	if !ok {
		return
	}
	var in branchCreateIn
	if !a.readJSON(w, r, &in, false) {
		return
	}
	in.Name, in.From = strings.TrimSpace(in.Name), strings.TrimSpace(in.From)
	if !gitsource.ValidBranch(in.Name) {
		badRequest(w, "invalid branch name")
		return
	}
	if !validRefName(in.From) {
		badRequest(w, "from must be a branch, tag or commit")
		return
	}
	ctx, ok := a.asUser(w, sc, false)
	if !ok {
		return
	}
	b, err := sc.core.CreateBranch(ctx, sc.ref, in.Name, in.From)
	if err != nil {
		a.fail(w, err, true)
		return
	}
	respondJSON(w, http.StatusCreated, gitapi.ToBranch(*b))
}

// branchDelete: DELETE .../git/branches/{branch}. Refuses the default branch and protected ones.
func (a *gitAPI) branchDelete(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitWrite)
	if !ok {
		return
	}
	name := pathName(r, "*")
	if !gitsource.ValidBranch(name) {
		badRequest(w, "invalid branch name")
		return
	}
	def, _, err := a.defaultBranch(sc)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	if name == def {
		respondError(w, http.StatusConflict, "PROTECTED_BRANCH", "the default branch cannot be deleted")
		return
	}
	b, err := sc.core.GetBranch(sc.ctx, sc.ref, name)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	if b.Protected {
		respondError(w, http.StatusConflict, "PROTECTED_BRANCH", "the branch is protected; remove its protection rule first")
		return
	}
	ctx, ok := a.asUser(w, sc, false)
	if !ok {
		return
	}
	if err := sc.core.DeleteBranch(ctx, sc.ref, name); err != nil {
		a.fail(w, err, true)
		return
	}
	respondNoContent(w)
}

// ---- tags -----------------------------------------------------------------------------------

// tagsList: GET .../git/tags
func (a *gitAPI) tagsList(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitRead)
	if !ok {
		return
	}
	pg, ok := pageParams(w, r)
	if !ok {
		return
	}
	l, err := sc.core.ListTags(sc.ctx, sc.ref, pg)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusOK, newList(l.Items, l.NextCursor))
}

type tagCreateIn struct {
	Name    string `json:"name"`
	Target  string `json:"target"`
	Message string `json:"message"`
}

// tagCreate: POST .../git/tags (tag protection is enforced by Forgejo and surfaces as 409).
func (a *gitAPI) tagCreate(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitWrite)
	if !ok {
		return
	}
	var in tagCreateIn
	if !a.readJSON(w, r, &in, false) {
		return
	}
	in.Name, in.Target = strings.TrimSpace(in.Name), strings.TrimSpace(in.Target)
	if !gitsource.ValidBranch(in.Name) {
		badRequest(w, "invalid tag name")
		return
	}
	if !validRefName(in.Target) {
		badRequest(w, "target must be a branch or commit")
		return
	}
	if len(in.Message) > 4096 {
		badRequest(w, "message is too long")
		return
	}
	if !a.guardTag(w, sc, in.Name, "crearla") {
		return
	}
	ctx, ok := a.asUser(w, sc, false)
	if !ok {
		return
	}
	t, err := sc.core.CreateTag(ctx, sc.ref, in.Name, in.Target, in.Message)
	if err != nil {
		if tagRefused(w, err) {
			return
		}
		a.fail(w, err, true)
		return
	}
	respondJSON(w, http.StatusCreated, t)
}

// tagDelete: DELETE .../git/tags/{tag}
func (a *gitAPI) tagDelete(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitWrite)
	if !ok {
		return
	}
	name := pathName(r, "*")
	if !gitsource.ValidBranch(name) {
		badRequest(w, "invalid tag name")
		return
	}
	if !a.guardTag(w, sc, name, "borrarla") {
		return
	}
	ctx, ok := a.asUser(w, sc, false)
	if !ok {
		return
	}
	if err := sc.core.DeleteTag(ctx, sc.ref, name); err != nil {
		if tagRefused(w, err) {
			return
		}
		a.fail(w, err, true)
		return
	}
	respondNoContent(w)
}

// ---- commits --------------------------------------------------------------------------------

// commitsList: GET .../git/commits?branch=
func (a *gitAPI) commitsList(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scopeAuth(w, r, authz.GitRead)
	if !ok {
		return
	}
	if a.legacyProvider(sc) {
		a.d.Legacy.Commits(w, r)
		return
	}
	if !sc.core.Enabled() {
		respondError(w, http.StatusServiceUnavailable, "GIT_NOT_READY", "the Git service is not configured on this server")
		return
	}
	pg, ok := pageParams(w, r)
	if !ok {
		return
	}
	branch := strings.TrimSpace(r.URL.Query().Get("branch"))
	if branch != "" && !validRefName(branch) {
		badRequest(w, "invalid branch")
		return
	}
	l, err := sc.core.ListCommits(sc.ctx, sc.ref, gitcore.CommitQuery{Ref: branch}, pg)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	respondJSON(w, http.StatusOK, newLegacyList(l.Items, l.NextCursor))
}

type commitOut struct {
	gitcore.Commit
	FilesTruncated bool `json:"files_truncated,omitempty"`
}

// commitGet: GET .../git/commits/{sha}: the commit with its changed files (bounded diff).
func (a *gitAPI) commitGet(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitRead)
	if !ok {
		return
	}
	sha := strings.TrimSpace(pathName(r, "sha"))
	if !validRefName(sha) {
		badRequest(w, "invalid commit")
		return
	}
	c, err := sc.core.GetCommit(sc.ctx, sc.ref, sha)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	out := commitOut{Commit: *c}
	if d, err := sc.core.CommitDiff(sc.ctx, sc.ref, c.SHA); err == nil {
		out.Files, out.FilesTruncated = d.Files, d.Truncated
	} else if !errors.Is(err, gitcore.ErrNotFound) {
		a.fail(w, err, false)
		return
	}
	if out.Files == nil {
		out.Files = []gitcore.FileDiff{}
	}
	if out.Parents == nil {
		out.Parents = []string{}
	}
	respondJSON(w, http.StatusOK, out)
}

// commitChecks: GET .../git/commits/{sha}/checks
func (a *gitAPI) commitChecks(w http.ResponseWriter, r *http.Request) {
	sc, ok := a.scope(w, r, authz.GitRead)
	if !ok {
		return
	}
	sha := strings.TrimSpace(pathName(r, "sha"))
	if !validRefName(sha) {
		badRequest(w, "invalid commit")
		return
	}
	cs, err := sc.core.ListChecks(sc.ctx, sc.ref, sha)
	if err != nil {
		a.fail(w, err, false)
		return
	}
	// "required" is relative to the default branch rule: a commit has no target branch.
	var rule *gitcore.ProtectionSpec
	if def, _, err := a.defaultBranch(sc); err == nil {
		if rules, err := sc.core.ListProtections(sc.ctx, sc.ref); err == nil {
			rule = gitapi.MatchRule(rules, def)
		}
	}
	respondJSON(w, http.StatusOK, gitapi.ToCheckList(cs, rule))
}
