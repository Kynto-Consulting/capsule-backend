package gitcore

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// ---- upstream shapes ---------------------------------------------------------------------------

type fgPayloadUser struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

type fgBranch struct {
	Name   string `json:"name"`
	Commit struct {
		ID        string        `json:"id"`
		Message   string        `json:"message"`
		Timestamp string        `json:"timestamp"`
		Author    fgPayloadUser `json:"author"`
	} `json:"commit"`
	Protected     bool   `json:"protected"`
	EffectiveRule string `json:"effective_branch_protection_name"`
}

type fgCommitUser struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Date  string `json:"date"`
}

type fgCommit struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
	Created string `json:"created"`
	Commit  struct {
		Message      string       `json:"message"`
		Author       fgCommitUser `json:"author"`
		Verification struct {
			Verified bool `json:"verified"`
		} `json:"verification"`
	} `json:"commit"`
	Author  *fgUser `json:"author"`
	Parents []struct {
		SHA string `json:"sha"`
	} `json:"parents"`
	Files []struct {
		Filename string `json:"filename"`
		Status   string `json:"status"`
	} `json:"files"`
}

func (c fgCommit) commit() Commit {
	p := Person{Name: c.Commit.Author.Name, Email: c.Commit.Author.Email}
	if c.Author != nil {
		p = c.Author.person()
		if p.Name == "" {
			p.Name = c.Commit.Author.Name
		}
		if p.Email == "" {
			p.Email = c.Commit.Author.Email
		}
	}
	at := parseTime(c.Commit.Author.Date)
	if at.IsZero() {
		at = parseTime(c.Created)
	}
	out := Commit{SHA: c.SHA, Message: c.Commit.Message, Author: p, CommittedAt: at,
		Verified: c.Commit.Verification.Verified, URL: c.HTMLURL, Parents: []string{}}
	for _, pa := range c.Parents {
		out.Parents = append(out.Parents, pa.SHA)
	}
	for _, f := range c.Files {
		out.Files = append(out.Files, FileDiff{Path: f.Filename, Status: normStatus(f.Status)})
	}
	return out
}

func normStatus(s string) string {
	switch s {
	case "added", "modified", "removed", "renamed":
		return s
	case "deleted":
		return "removed"
	case "changed":
		return "modified"
	}
	return "modified"
}

// ---- branches ----------------------------------------------------------------------------------

func (s *Service) ListBranches(ctx context.Context, r RepoRef, p Page) (List[Branch], error) {
	if err := r.valid(); err != nil {
		return List[Branch]{}, err
	}
	key := s.listKey(ctx, r, "branches", p.Cursor, itoa(clampLimit(p.Limit)))
	return cached(ctx, s, key, s.cfg.ListTTL, func() (List[Branch], error) {
		items, next, err := fetchPaged[fgBranch](ctx, s, req{method: http.MethodGet, path: r.base() + "/branches", op: "/repos/{o}/{r}/branches"}, p, "", nil)
		if err != nil {
			return List[Branch]{}, err
		}
		def := ""
		if repo, rerr := s.GetRepo(ctx, r); rerr == nil {
			def = repo.DefaultBranch
		}
		out := List[Branch]{Items: make([]Branch, 0, len(items)), NextCursor: next}
		for _, b := range items {
			out.Items = append(out.Items, b.branch(def))
		}
		return out, nil
	})
}

func (b fgBranch) branch(def string) Branch {
	return Branch{Name: b.Name, SHA: b.Commit.ID, Protected: b.Protected, ProtectionRule: b.EffectiveRule,
		Default: def != "" && b.Name == def, UpdatedAt: parseTime(b.Commit.Timestamp),
		Author: b.Commit.Author.Name, Message: b.Commit.Message}
}

func (s *Service) GetBranch(ctx context.Context, r RepoRef, name string) (*Branch, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, invalid("branch name is required")
	}
	var f fgBranch
	if _, err := s.do(ctx, req{method: http.MethodGet, path: r.base() + "/branches/" + escPath(name), op: "/repos/{o}/{r}/branches/{b}"}, &f); err != nil {
		return nil, err
	}
	def := ""
	if repo, err := s.GetRepo(ctx, r); err == nil {
		def = repo.DefaultBranch
	}
	b := f.branch(def)
	return &b, nil
}

func (s *Service) CreateBranch(ctx context.Context, r RepoRef, name, from string) (*Branch, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if name == "" || from == "" {
		return nil, invalid("branch name and source are required")
	}
	var f fgBranch
	// old_ref_name accepts branch, tag or commit; old_branch_name is the deprecated spelling (?).
	_, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/branches", op: "/repos/{o}/{r}/branches",
		body: map[string]any{"new_branch_name": name, "old_ref_name": from}}, &f)
	if err != nil {
		return nil, err
	}
	_ = s.InvalidateRepo(ctx, r)
	b := f.branch("")
	return &b, nil
}

func (s *Service) DeleteBranch(ctx context.Context, r RepoRef, name string) error {
	if err := r.valid(); err != nil {
		return err
	}
	if name == "" {
		return invalid("branch name is required")
	}
	_, err := s.do(ctx, req{method: http.MethodDelete, path: r.base() + "/branches/" + escPath(name), op: "/repos/{o}/{r}/branches/{b}"}, nil)
	if err == nil {
		_ = s.InvalidateRepo(ctx, r)
	}
	return err
}

// ---- tags --------------------------------------------------------------------------------------

type fgTag struct {
	Name    string `json:"name"`
	ID      string `json:"id"`
	Message string `json:"message"`
	Commit  struct {
		SHA     string `json:"sha"`
		Created string `json:"created"`
	} `json:"commit"`
}

func (t fgTag) tag() Tag {
	sha := t.Commit.SHA
	if sha == "" {
		sha = t.ID
	}
	return Tag{Name: t.Name, SHA: sha, Message: t.Message, CreatedAt: parseTime(t.Commit.Created)}
}

func (s *Service) ListTags(ctx context.Context, r RepoRef, p Page) (List[Tag], error) {
	if err := r.valid(); err != nil {
		return List[Tag]{}, err
	}
	key := s.listKey(ctx, r, "tags", p.Cursor, itoa(clampLimit(p.Limit)))
	return cached(ctx, s, key, s.cfg.ListTTL, func() (List[Tag], error) {
		items, next, err := fetchPaged[fgTag](ctx, s, req{method: http.MethodGet, path: r.base() + "/tags", op: "/repos/{o}/{r}/tags"}, p, "", nil)
		if err != nil {
			return List[Tag]{}, err
		}
		out := List[Tag]{Items: make([]Tag, 0, len(items)), NextCursor: next}
		for _, t := range items {
			out.Items = append(out.Items, t.tag())
		}
		return out, nil
	})
}

func (s *Service) CreateTag(ctx context.Context, r RepoRef, name, target, message string) (*Tag, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if name == "" || target == "" {
		return nil, invalid("tag name and target are required")
	}
	var f fgTag
	_, err := s.do(ctx, req{method: http.MethodPost, path: r.base() + "/tags", op: "/repos/{o}/{r}/tags",
		body: map[string]any{"tag_name": name, "target": target, "message": message}}, &f)
	if err != nil {
		return nil, err
	}
	_ = s.InvalidateRepo(ctx, r)
	t := f.tag()
	return &t, nil
}

func (s *Service) DeleteTag(ctx context.Context, r RepoRef, name string) error {
	if err := r.valid(); err != nil {
		return err
	}
	if name == "" {
		return invalid("tag name is required")
	}
	_, err := s.do(ctx, req{method: http.MethodDelete, path: r.base() + "/tags/" + escPath(name), op: "/repos/{o}/{r}/tags/{t}"}, nil)
	if err == nil {
		_ = s.InvalidateRepo(ctx, r)
	}
	return err
}

// ---- commits -----------------------------------------------------------------------------------

func (s *Service) ListCommits(ctx context.Context, r RepoRef, q CommitQuery, p Page) (List[Commit], error) {
	if err := r.valid(); err != nil {
		return List[Commit]{}, err
	}
	// A branch/tag ref moves, so lists are short-lived; a full SHA ref is immutable.
	build := func() (List[Commit], error) {
		qv := url.Values{"stat": {"false"}, "verification": {"true"}, "files": {"false"}}
		if q.Ref != "" {
			qv.Set("sha", q.Ref)
		}
		if q.Path != "" {
			qv.Set("path", q.Path)
		}
		items, next, err := fetchPaged[fgCommit](ctx, s, req{method: http.MethodGet, path: r.base() + "/commits", op: "/repos/{o}/{r}/commits", query: qv}, p, "", nil)
		if err != nil {
			return List[Commit]{}, err
		}
		out := List[Commit]{Items: make([]Commit, 0, len(items)), NextCursor: next}
		for _, c := range items {
			out.Items = append(out.Items, c.commit())
		}
		return out, nil
	}
	parts := []string{q.Ref, q.Path, p.Cursor, itoa(clampLimit(p.Limit))}
	if isHexSHA(q.Ref) {
		return cached(ctx, s, immKey(r, "commits", parts...), s.cfg.ImmutableTTL, build)
	}
	return cached(ctx, s, s.listKey(ctx, r, "commits", parts...), s.cfg.ListTTL, build)
}

func (s *Service) GetCommit(ctx context.Context, r RepoRef, sha string) (*Commit, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if sha == "" {
		return nil, invalid("commit sha is required")
	}
	fetch := func() (Commit, error) {
		var f fgCommit
		if _, err := s.do(ctx, req{method: http.MethodGet, path: r.base() + "/git/commits/" + esc(sha), op: "/repos/{o}/{r}/git/commits/{sha}"}, &f); err != nil {
			return Commit{}, err
		}
		return f.commit(), nil
	}
	var c Commit
	var err error
	if isHexSHA(sha) {
		c, err = cached(ctx, s, immKey(r, "commit", sha), s.cfg.ImmutableTTL, fetch)
	} else {
		c, err = fetch() // a ref name moves: never cache
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Service) CommitDiff(ctx context.Context, r RepoRef, sha string) (*Diff, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if sha == "" {
		return nil, invalid("commit sha is required")
	}
	fetch := func() (Diff, error) {
		res, err := s.do(ctx, req{method: http.MethodGet, path: r.base() + "/git/commits/" + esc(sha) + ".diff",
			op: "/repos/{o}/{r}/git/commits/{sha}.diff", accept: "text/plain"}, nil)
		if errIs(err, CodeTooLarge) {
			return Diff{Files: []FileDiff{}, Truncated: true}, nil
		}
		if err != nil {
			return Diff{}, err
		}
		return parseDiff(string(res.body), MaxDiffBytes), nil
	}
	var d Diff
	var err error
	if isHexSHA(sha) {
		d, err = cached(ctx, s, immKey(r, "cdiff", sha), s.cfg.ImmutableTTL, fetch)
	} else {
		d, err = fetch()
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// ---- tree and blobs ----------------------------------------------------------------------------

type fgContent struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	SHA      string `json:"sha"`
	Type     string `json:"type"`
	Size     int64  `json:"size"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

func normType(t string) string {
	switch t {
	case "dir", "tree":
		return "dir"
	case "symlink":
		return "symlink"
	case "submodule", "commit":
		return "submodule"
	}
	return "file"
}

// ListTree lists one directory (not recursive) through the contents API, which returns the
// whole directory; paging is applied locally with offset cursors.
func (s *Service) ListTree(ctx context.Context, r RepoRef, ref, dir string, p Page) (List[TreeEntry], error) {
	if err := r.valid(); err != nil {
		return List[TreeEntry]{}, err
	}
	dir = strings.Trim(dir, "/")
	fetch := func() ([]TreeEntry, error) {
		path := r.base() + "/contents"
		if dir != "" {
			path += "/" + escPath(dir)
		}
		qv := url.Values{}
		if ref != "" {
			qv.Set("ref", ref)
		}
		var raw []fgContent
		res, err := s.do(ctx, req{method: http.MethodGet, path: path, op: "/repos/{o}/{r}/contents/{path}", query: qv}, nil)
		if err != nil {
			return nil, err
		}
		if jerr := jsonInto(res.body, &raw); jerr != nil {
			// A file path answers with an object, not an array: it is not a directory.
			return nil, &Error{Code: CodeNotFound, Status: 404, Message: "path is not a directory", Op: "GET /repos/{o}/{r}/contents/{path}"}
		}
		out := make([]TreeEntry, 0, len(raw))
		for _, c := range raw {
			out = append(out, TreeEntry{Name: c.Name, Path: c.Path, Type: normType(c.Type), Size: c.Size, SHA: c.SHA})
		}
		return out, nil
	}
	var all []TreeEntry
	var err error
	if isHexSHA(ref) {
		all, err = cached(ctx, s, immKey(r, "tree", ref, dir), s.cfg.ImmutableTTL, fetch)
	} else {
		all, err = cached(ctx, s, s.listKey(ctx, r, "tree", ref, dir), s.cfg.ListTTL, fetch)
	}
	if err != nil {
		return List[TreeEntry]{}, err
	}
	// Directories first, then by name: the order every code browser shows.
	sortTree(all)
	return pageSlice(all, p)
}

func (s *Service) GetFile(ctx context.Context, r RepoRef, ref, path string) (*Blob, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	path = strings.Trim(path, "/")
	if path == "" {
		return nil, invalid("file path is required")
	}
	fetch := func() (Blob, error) {
		qv := url.Values{}
		if ref != "" {
			qv.Set("ref", ref)
		}
		var c fgContent
		_, err := s.do(ctx, req{method: http.MethodGet, path: r.base() + "/contents/" + escPath(path), op: "/repos/{o}/{r}/contents/{path}", query: qv}, &c)
		if errIs(err, CodeTooLarge) {
			return Blob{Path: path, Truncated: true}, nil
		}
		if err != nil {
			return Blob{}, err
		}
		if c.Type != "" && c.Type != "file" && c.Type != "symlink" {
			return Blob{}, &Error{Code: CodeNotFound, Status: 404, Message: "path is not a file", Op: "GET /repos/{o}/{r}/contents/{path}"}
		}
		return makeBlob(path, c.SHA, c.Size, c.Content, c.Encoding), nil
	}
	var b Blob
	var err error
	if isHexSHA(ref) {
		b, err = cached(ctx, s, immKey(r, "file", ref, path), s.cfg.ImmutableTTL, fetch)
	} else {
		b, err = fetch()
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func (s *Service) GetBlob(ctx context.Context, r RepoRef, sha string) (*Blob, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if !isHexSHA(sha) {
		return nil, invalid("blob sha must be a full hex object id")
	}
	b, err := cached(ctx, s, immKey(r, "blob", sha), s.cfg.ImmutableTTL, func() (Blob, error) {
		var c fgContent
		_, err := s.do(ctx, req{method: http.MethodGet, path: r.base() + "/git/blobs/" + esc(sha), op: "/repos/{o}/{r}/git/blobs/{sha}"}, &c)
		if errIs(err, CodeTooLarge) {
			return Blob{SHA: sha, Truncated: true}, nil
		}
		if err != nil {
			return Blob{}, err
		}
		if c.SHA == "" {
			c.SHA = sha
		}
		return makeBlob("", c.SHA, c.Size, c.Content, c.Encoding), nil
	})
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// makeBlob decodes Forgejo's base64 payload, applies the 1 MiB cap and detects binary content.
func makeBlob(path, sha string, size int64, content, encoding string) Blob {
	b := Blob{Path: path, SHA: sha, Size: size}
	if size > MaxBlobBytes {
		b.Truncated = true
		return b
	}
	raw := []byte(content)
	if encoding == "base64" {
		dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(content, "\n", ""))
		if err != nil {
			b.Truncated = true
			return b
		}
		raw = dec
	}
	if b.Size == 0 {
		b.Size = int64(len(raw))
	}
	if int64(len(raw)) > MaxBlobBytes {
		b.Truncated, b.Size = true, int64(len(raw))
		return b
	}
	sample := raw
	if len(sample) > 8000 {
		sample = sample[:8000]
	}
	// Binary = NUL byte in the first 8000 bytes (git's own heuristic) or invalid UTF-8.
	if strings.IndexByte(string(sample), 0) >= 0 || !utf8.Valid(raw) {
		b.Binary = true
	}
	if b.Binary {
		b.Encoding, b.Content = "base64", base64.StdEncoding.EncodeToString(raw)
	} else {
		b.Encoding, b.Content = "utf-8", string(raw)
	}
	return b
}

// ---- compare -----------------------------------------------------------------------------------

func (s *Service) Compare(ctx context.Context, r RepoRef, base, head string) (*Compare, error) {
	if err := r.valid(); err != nil {
		return nil, err
	}
	if base == "" || head == "" {
		return nil, invalid("base and head are required")
	}
	fetch := func() (Compare, error) {
		var f struct {
			Total   int        `json:"total_commits"`
			Commits []fgCommit `json:"commits"`
			Files   []struct {
				Filename string `json:"filename"`
				Status   string `json:"status"`
			} `json:"files"`
		}
		// basehead is "base...head"; both sides are escaped but the dots stay.
		path := r.base() + "/compare/" + escPath(base) + "..." + escPath(head)
		if _, err := s.do(ctx, req{method: http.MethodGet, path: path, op: "/repos/{o}/{r}/compare/{basehead}"}, &f); err != nil {
			return Compare{}, err
		}
		c := Compare{AheadBy: f.Total, Commits: []Commit{}, Files: []FileDiff{}}
		if c.AheadBy == 0 {
			c.AheadBy = len(f.Commits)
		}
		for _, cm := range f.Commits {
			c.Commits = append(c.Commits, cm.commit())
		}
		for _, fl := range f.Files {
			c.Files = append(c.Files, FileDiff{Path: fl.Filename, Status: normStatus(fl.Status)})
		}
		return c, nil
	}
	var c Compare
	var err error
	if isHexSHA(base) && isHexSHA(head) {
		c, err = cached(ctx, s, immKey(r, "compare", base, head), s.cfg.ImmutableTTL, fetch)
	} else {
		c, err = cached(ctx, s, s.listKey(ctx, r, "compare", base, head), s.cfg.ListTTL, fetch)
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}
