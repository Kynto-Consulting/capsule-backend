package gittokens

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// Op is what a Git HTTP request does to the repository.
type Op string

const (
	OpRead  Op = "read"
	OpWrite Op = "write"
)

// Target is the repository and operation of a Git-over-HTTP request.
type Target struct {
	Owner string // Forgejo owner = Capsule org slug (lowercased)
	Repo  string // Forgejo repo = Capsule project slug (lowercased, ".git" removed)
	Op    Op
}

var errBadTarget = errors.New("not a recognized git request")

var (
	reSlug       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,98}$`)
	reLooseObj   = regexp.MustCompile(`^objects/[0-9a-f]{2}/[0-9a-f]{38,62}$`)
	rePackFile   = regexp.MustCompile(`^objects/pack/pack-[0-9a-f]{40,64}\.(pack|idx)$`)
	reLFSPath    = regexp.MustCompile(`^info/lfs/(objects(/[A-Za-z0-9_./-]+)?|verify|locks(/[A-Za-z0-9_./-]+)?)$`)
	reLFSBatch   = regexp.MustCompile(`^info/lfs/objects/batch$`)
	reControlOrN = regexp.MustCompile("[\\x00-\\x20\\x7f\\\\%]")
)

// ClassifyGitRequest turns the original request (Caddy's X-Forwarded-Method and X-Forwarded-Uri)
// into the repository and operation it touches. It is deliberately strict: anything that is not
// one of the Git smart/dumb HTTP or LFS routes, or whose path is not already canonical (dot
// segments, doubled slashes, percent escapes, backslashes), is rejected, so the repo checked
// here is the repo Forgejo will serve.
//
// Read vs write follows the protocol: git-upload-pack and plain GETs read; git-receive-pack and
// LFS uploads write. LFS "batch" is allowed for read tokens: it only announces the transfer, the
// upload itself (PUT) needs write.
func ClassifyGitRequest(method, rawURI string) (Target, error) {
	method = strings.ToUpper(method)
	u, err := url.ParseRequestURI(rawURI)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Path == "" || u.Path[0] != '/' {
		return Target{}, errBadTarget
	}
	path := u.EscapedPath()
	if reControlOrN.MatchString(path) || strings.Contains(path, "//") {
		return Target{}, errBadTarget
	}
	for _, seg := range strings.Split(path[1:], "/") {
		if seg == "." || seg == ".." || seg == "" {
			return Target{}, errBadTarget
		}
	}
	parts := strings.SplitN(path[1:], "/", 3)
	if len(parts) < 3 {
		return Target{}, errBadTarget
	}
	owner, repo, rest := parts[0], strings.TrimSuffix(parts[1], ".git"), parts[2]
	if !reSlug.MatchString(owner) || !reSlug.MatchString(repo) {
		return Target{}, errBadTarget
	}
	t := Target{Owner: strings.ToLower(owner), Repo: strings.ToLower(repo)}

	switch {
	case rest == "info/refs":
		if method != "GET" && method != "HEAD" {
			return Target{}, errBadTarget
		}
		switch u.Query().Get("service") {
		case "", "git-upload-pack":
			t.Op = OpRead
		case "git-receive-pack":
			t.Op = OpWrite
		default:
			return Target{}, errBadTarget
		}
	case rest == "git-upload-pack":
		if method != "POST" {
			return Target{}, errBadTarget
		}
		t.Op = OpRead
	case rest == "git-receive-pack":
		if method != "POST" {
			return Target{}, errBadTarget
		}
		t.Op = OpWrite
	case rest == "HEAD" || reLooseObj.MatchString(rest) || rePackFile.MatchString(rest) || rest == "objects/info/packs":
		if method != "GET" && method != "HEAD" {
			return Target{}, errBadTarget
		}
		t.Op = OpRead
	case reLFSBatch.MatchString(rest):
		if method != "POST" {
			return Target{}, errBadTarget
		}
		t.Op = OpRead
	case reLFSPath.MatchString(rest):
		if method == "GET" || method == "HEAD" {
			t.Op = OpRead
		} else {
			t.Op = OpWrite
		}
	default:
		return Target{}, errBadTarget
	}
	return t, nil
}
