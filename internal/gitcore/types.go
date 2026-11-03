// Package gitcore is the ONLY door from the Capsule backend to Forgejo (Git Capsule, package A1).
//
// Every other package (A2 identity, A4 protections, A5 events, A6 environments, A7 tokens,
// B1 API, B6-B8, C1, C3) is written against the interfaces and DTOs in THIS file. It is fixed:
// add fields only if strictly necessary, never rename or remove.
//
// Conventions:
//   - Calls act as the service account unless the context carries an actor (WithActor): then the
//     request goes out with the Forgejo "Sudo: <login>" header, so authorship in Forgejo is the
//     real user. Capsule decides permissions BEFORE calling (authz); gitcore never decides them.
//   - Lists are paginated with opaque cursors (Page / List). The cursor is translated to
//     Forgejo page/limit internally.
//   - Every error returned is a *Error (use errors.Is with the Err* sentinels, or AsError).
//     Error messages never contain the service token or any header.
//   - DTOs are Capsule-shaped (they mirror docs/git-capsule/API.openapi.yaml schemas), not raw
//     Forgejo JSON. Fields marked (?) were not confirmed against a running Forgejo.
package gitcore

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------------------------
// Errors (normalized)
// ---------------------------------------------------------------------------------------------

// Code is the normalized error code. HTTPStatus gives the status B1 should answer with.
type Code string

const (
	CodeUpstream    Code = "UPSTREAM_GIT_ERROR" // Forgejo unreachable, 5xx, 429, 401 (bad service token), bad body: 502
	CodeNotReady    Code = "GIT_NOT_READY"      // integration off, circuit open, repo not provisioned: 503
	CodeNotFound    Code = "NOT_FOUND"          // 404 upstream: 404
	CodeForbidden   Code = "FORBIDDEN"          // 403 upstream (branch protection, sudo denied...): 403
	CodeConflict    Code = "CONFLICT"           // 409 upstream (merge conflict, head moved, exists): 409
	CodeUnprocessed Code = "UNPROCESSABLE"      // 422 / 400 upstream validation: 422
	CodeTooLarge    Code = "TOO_LARGE"          // payload over a gitcore limit (413 upstream): 413
	CodeInvalid     Code = "INVALID_ARGUMENT"   // bad input detected locally (never sent): 400
)

// Error is the only error type gitcore returns.
type Error struct {
	Code     Code
	Status   int    // upstream HTTP status (0 if none)
	Message  string // safe to show: truncated, token scrubbed
	Op       string // e.g. "GET /repos/{o}/{r}/branches" (path template, no secrets)
	Retry    bool   // the same call may succeed later (upstream down / breaker)
	Cause    error  // unexported detail for logs; never rendered by Error()
	causeMsg string
}

func (e *Error) Error() string {
	if e.Op == "" {
		return fmt.Sprintf("gitcore: %s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("gitcore: %s: %s (%s)", e.Code, e.Message, e.Op)
}

// Is makes errors.Is(err, ErrNotFound) etc. compare codes.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code && t.Op == "" && t.Message == ""
}

// Unwrap exposes the (already scrubbed) cause for errors.Is(context.DeadlineExceeded).
func (e *Error) Unwrap() error { return e.Cause }

// HTTPStatus is the status B1 should return to the browser/CLI for this error.
func (e *Error) HTTPStatus() int {
	switch e.Code {
	case CodeNotFound:
		return 404
	case CodeForbidden:
		return 403
	case CodeConflict:
		return 409
	case CodeUnprocessed:
		return 422
	case CodeTooLarge:
		return 413
	case CodeInvalid:
		return 400
	case CodeNotReady:
		return 503
	default:
		return 502
	}
}

// Sentinels for errors.Is.
var (
	ErrUpstream    = &Error{Code: CodeUpstream}
	ErrNotReady    = &Error{Code: CodeNotReady}
	ErrNotFound    = &Error{Code: CodeNotFound}
	ErrForbidden   = &Error{Code: CodeForbidden}
	ErrConflict    = &Error{Code: CodeConflict}
	ErrUnprocessed = &Error{Code: CodeUnprocessed}
	ErrTooLarge    = &Error{Code: CodeTooLarge}
	ErrInvalid     = &Error{Code: CodeInvalid}
)

// AsError extracts the *Error from err (nil, false if it is not one).
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// ---------------------------------------------------------------------------------------------
// Acting as a user (Sudo)
// ---------------------------------------------------------------------------------------------

type actorKey struct{}

// WithActor returns a context whose Forgejo calls are made with "Sudo: login".
// An empty login returns ctx unchanged (service account).
func WithActor(ctx context.Context, forgejoLogin string) context.Context {
	if forgejoLogin == "" {
		return ctx
	}
	return context.WithValue(ctx, actorKey{}, forgejoLogin)
}

// ActorFrom returns the login set by WithActor ("" = service account).
func ActorFrom(ctx context.Context) string {
	s, _ := ctx.Value(actorKey{}).(string)
	return s
}

// ---------------------------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------------------------

// Page is the request side of cursor pagination. Zero value = first page, DefaultLimit items.
type Page struct {
	Cursor string // opaque, from List.NextCursor; "" = first page
	Limit  int    // 1..MaxLimit (clamped); 0 = DefaultLimit
}

const (
	DefaultLimit = 30
	MaxLimit     = 100
)

// List is one page of results. NextCursor == "" means there is no more.
type List[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// Size limits enforced by gitcore (fixed by SPEC / WORKBREAKDOWN A1).
const (
	MaxBlobBytes = 1 << 20 // blobs above this come back Truncated with no content
	MaxDiffBytes = 2 << 20 // total diff of a PR/commit/compare above this is cut, Truncated=true
	MaxLogBytes  = 1 << 20 // default cap for job logs
)

// ---------------------------------------------------------------------------------------------
// Repo coordinates and repositories
// ---------------------------------------------------------------------------------------------

// RepoRef identifies a repository (owner = Capsule org slug, repo = project slug).
type RepoRef struct {
	Owner string
	Repo  string
}

func (r RepoRef) String() string { return r.Owner + "/" + r.Repo }

// Person is a Forgejo user as shown in Capsule.
type Person struct {
	Login     string `json:"login"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
}

// Repository is the subset of a Forgejo repository Capsule uses.
type Repository struct {
	Owner              string   `json:"owner"`
	Name               string   `json:"name"`
	DefaultBranch      string   `json:"default_branch"`
	Private            bool     `json:"private"`
	Empty              bool     `json:"empty"`
	Archived           bool     `json:"archived"`
	SizeKB             int64    `json:"size_kb"`
	HTMLURL            string   `json:"html_url"`
	DeleteBranchOnPR   bool     `json:"delete_branch_on_merge"`
	AllowedMergeStyles []string `json:"allowed_merge_styles"` // merge|squash|rebase|fast-forward
}

// RepoCreate creates a repository in an organization.
type RepoCreate struct {
	Name          string
	Private       bool
	AutoInit      bool
	DefaultBranch string
	Description   string
}

// RepoPatch changes repository settings; nil fields are left alone. (?) names of the merge
// style flags (allow_merge_commits, allow_squash_merge, allow_rebase, allow_fast_forward_only_merge).
type RepoPatch struct {
	DefaultBranch      *string
	Archived           *bool
	DeleteBranchOnPR   *bool
	AllowedMergeStyles []string // nil = untouched; non-nil replaces the whole set
}

// MigrateSpec imports (or mirrors, Mirror=true) an external repository.
type MigrateSpec struct {
	Owner, Repo  string
	CloneAddr    string
	AuthToken    string // external token (secret; never logged)
	Service      string // git|github|gitea|gitlab|forgejo (default git)
	Mirror       bool
	MirrorEvery  string // "8h0m0s" format (?)
	Private      bool
	Issues       bool
	PullRequests bool
	Releases     bool
	Wiki         bool
	LFS          bool
}

// ---------------------------------------------------------------------------------------------
// Branches, tags, commits, tree, blobs, compare
// ---------------------------------------------------------------------------------------------

type Branch struct {
	Name           string    `json:"name"`
	SHA            string    `json:"sha"`
	Protected      bool      `json:"protected"`
	ProtectionRule string    `json:"protection_rule,omitempty"` // Forgejo rule name (effective_branch_protection_name)
	Default        bool      `json:"default"`
	UpdatedAt      time.Time `json:"updated_at"`
	Author         string    `json:"author,omitempty"`
	Message        string    `json:"message,omitempty"`
}

type Tag struct {
	Name      string    `json:"name"`
	SHA       string    `json:"sha"`
	Message   string    `json:"message,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Commit struct {
	SHA         string     `json:"sha"`
	Message     string     `json:"message"`
	Author      Person     `json:"author"`
	CommittedAt time.Time  `json:"committed_at"`
	Verified    bool       `json:"verified"`
	Parents     []string   `json:"parents"`
	URL         string     `json:"url,omitempty"`
	Files       []FileDiff `json:"files,omitempty"`
}

// CommitQuery filters commit lists.
type CommitQuery struct {
	Ref  string // branch, tag or sha; "" = default branch
	Path string // only commits touching this path
}

type FileDiff struct {
	Path      string `json:"path"`
	OldPath   string `json:"old_path,omitempty"`
	Status    string `json:"status"` // added|modified|removed|renamed
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	Patch     string `json:"patch,omitempty"`
	Truncated bool   `json:"truncated,omitempty"` // patch cut by MaxDiffBytes (or binary: no patch)
}

// Diff is a bounded diff (PR, commit or compare). Truncated => later files carry no patch.
type Diff struct {
	Files     []FileDiff `json:"files"`
	Truncated bool       `json:"truncated"`
	Bytes     int        `json:"bytes"`
}

type TreeEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"` // file|dir|symlink|submodule
	Size int64  `json:"size"`
	SHA  string `json:"sha"`
	Mode string `json:"mode,omitempty"`
}

type Blob struct {
	Path      string `json:"path,omitempty"`
	SHA       string `json:"sha"`
	Size      int64  `json:"size"`
	Binary    bool   `json:"binary"`
	Truncated bool   `json:"truncated"`          // Size > MaxBlobBytes: Content empty
	Encoding  string `json:"encoding,omitempty"` // utf-8|base64
	Content   string `json:"content,omitempty"`
}

type Compare struct {
	AheadBy   int        `json:"ahead_by"`
	BehindBy  int        `json:"behind_by"` // (?) Forgejo does not return it; 0 unless a reverse compare is made
	Commits   []Commit   `json:"commits"`
	Files     []FileDiff `json:"files"`
	Truncated bool       `json:"truncated"`
}

// ---------------------------------------------------------------------------------------------
// Pull requests, reviews, comments, merge
// ---------------------------------------------------------------------------------------------

type PullState string

const (
	PullOpen   PullState = "open"
	PullClosed PullState = "closed"
	PullMerged PullState = "merged"
)

type Pull struct {
	Number         int        `json:"number"`
	Title          string     `json:"title"`
	Body           string     `json:"body"`
	State          PullState  `json:"state"`
	Draft          bool       `json:"draft"`
	Head           string     `json:"head"`
	Base           string     `json:"base"`
	HeadSHA        string     `json:"head_sha"`
	BaseSHA        string     `json:"base_sha,omitempty"` // merge base when known
	Author         Person     `json:"author"`
	Reviewers      []Person   `json:"reviewers"`
	Labels         []string   `json:"labels"`
	Mergeable      bool       `json:"mergeable"` // Forgejo's own conflict check only; Capsule adds policy
	Merged         bool       `json:"merged"`
	MergeCommitSHA string     `json:"merge_commit_sha,omitempty"`
	HTMLURL        string     `json:"html_url"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	MergedAt       *time.Time `json:"merged_at,omitempty"`
}

// PullQuery filters pull request lists.
type PullQuery struct {
	State string // open|closed|all (default open)
	Base  string
	Head  string
}

type PullCreate struct {
	Title     string
	Body      string
	Head      string
	Base      string
	Draft     bool // implemented as the "WIP:" title prefix (?) — Forgejo has no draft flag on create
	Reviewers []string
}

type PullPatch struct {
	Title *string
	Body  *string
	Base  *string
	State *string // open|closed
	Draft *bool   // toggles the "WIP:" prefix (?)
}

type ReviewEvent string

const (
	ReviewApprove        ReviewEvent = "approve"
	ReviewRequestChanges ReviewEvent = "request_changes"
	ReviewComment        ReviewEvent = "comment"
)

type InlineComment struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Side string `json:"side,omitempty"` // left (old file) | right (new file, default)
	Body string `json:"body"`
}

type ReviewCreate struct {
	Event    ReviewEvent
	Body     string
	CommitID string
	Comments []InlineComment
}

type Review struct {
	ID          int64     `json:"id"`
	State       string    `json:"state"` // approved|changes_requested|commented|dismissed|pending
	Body        string    `json:"body"`
	Author      Person    `json:"author"`
	CommitSHA   string    `json:"commit_sha"`
	Stale       bool      `json:"stale"`
	Official    bool      `json:"official"`
	CommentsN   int       `json:"comments_count"`
	SubmittedAt time.Time `json:"submitted_at"`
}

type Comment struct {
	ID        int64      `json:"id"`
	Body      string     `json:"body"`
	Author    Person     `json:"author"`
	CreatedAt time.Time  `json:"created_at"`
	EditedAt  *time.Time `json:"edited_at,omitempty"`
}

type MergeStyle string

const (
	MergeCommit MergeStyle = "merge"
	MergeSquash MergeStyle = "squash"
	MergeRebase MergeStyle = "rebase"
	MergeFF     MergeStyle = "fast-forward"
)

type MergeRequest struct {
	Style        MergeStyle
	Title        string
	Message      string
	DeleteBranch bool
	HeadSHA      string // if set and the head moved, Forgejo answers 409 -> CodeConflict
	WhenChecks   bool   // merge_when_checks_succeed (Forgejo native auto-merge) (?)
	Force        bool   // force_merge: bypasses checks; Capsule must authorize it (admin only)
}

type MergeResult struct {
	Merged bool   `json:"merged"`
	Queued bool   `json:"queued"` // true when scheduled for "when checks succeed"
	SHA    string `json:"sha,omitempty"`
}

// ---------------------------------------------------------------------------------------------
// Checks (commit statuses)
// ---------------------------------------------------------------------------------------------

type CheckState string

const (
	CheckPending CheckState = "pending"
	CheckSuccess CheckState = "success"
	CheckFailure CheckState = "failure"
	CheckError   CheckState = "error"
	CheckSkipped CheckState = "skipped"
)

type Check struct {
	Context     string     `json:"context"`
	State       CheckState `json:"state"`
	TargetURL   string     `json:"target_url,omitempty"`
	Description string     `json:"description,omitempty"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type CheckSet struct {
	State CheckState `json:"state"` // combined: pending|success|failure
	Items []Check    `json:"items"`
}

type CheckInput struct {
	Context     string
	State       CheckState
	TargetURL   string
	Description string
}

// ---------------------------------------------------------------------------------------------
// Branch protection (Forgejo shape; A4 maps Capsule rules onto it)
// ---------------------------------------------------------------------------------------------

// ProtectionSpec mirrors Forgejo CreateBranchProtectionOption / EditBranchProtectionOption
// (verified against swagger 16.0.0-dev; NOT against v15.0.11 — (?)). Pointers are not used: the
// whole spec is sent, so A4 always sends the full desired state (idempotent).
type ProtectionSpec struct {
	RuleName                     string // the pattern (glob) Forgejo calls rule_name (branch_name is deprecated)
	EnablePush                   bool
	EnablePushWhitelist          bool
	PushWhitelistUsers           []string
	PushWhitelistTeams           []string
	PushWhitelistDeployKeys      bool
	EnableMergeWhitelist         bool
	MergeWhitelistUsers          []string
	MergeWhitelistTeams          []string
	EnableStatusCheck            bool
	StatusCheckContexts          []string
	RequiredApprovals            int
	EnableApprovalsWhitelist     bool
	ApprovalsWhitelistUsers      []string
	ApprovalsWhitelistTeams      []string
	BlockOnRejectedReviews       bool
	BlockOnOfficialReviewRequest bool
	BlockOnOutdatedBranch        bool
	DismissStaleApprovals        bool
	IgnoreStaleApprovals         bool
	RequireSignedCommits         bool
	ProtectedFilePatterns        string
	UnprotectedFilePatterns      string
	ApplyToAdmins                bool
}

type Protection struct {
	ProtectionSpec
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ---------------------------------------------------------------------------------------------
// Teams, members, hooks, keys, mirrors
// ---------------------------------------------------------------------------------------------

type Team struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Permission string `json:"permission"` // read|write|admin
}

type TeamSpec struct {
	Name       string
	Permission string   // read|write|admin
	Units      []string // default repo.code, repo.issues, repo.pulls, repo.releases
}

type Hook struct {
	ID     int64    `json:"id"`
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Active bool     `json:"active"`
}

// HookSpec: Secret is write-only (Forgejo never returns it).
type HookSpec struct {
	URL          string
	Secret       string
	Events       []string // e.g. push, pull_request, pull_request_review_approved, create, delete ...
	Type         string   // default forgejo
	BranchFilter string
	Active       bool
}

type SSHKey struct {
	ID          int64     `json:"id"`
	Title       string    `json:"title"`
	Fingerprint string    `json:"fingerprint"`
	Key         string    `json:"key,omitempty"`
	ReadOnly    bool      `json:"read_only"`
	CreatedAt   time.Time `json:"created_at"`
}

type PushMirrorSpec struct {
	RemoteAddress  string
	RemoteUsername string
	RemotePassword string // secret
	Interval       string // "8h0m0s"
	SyncOnCommit   bool
	UseSSH         bool
	BranchFilter   string
}

type PushMirror struct {
	RemoteName   string    `json:"remote_name"`
	RemoteURL    string    `json:"remote_address"`
	Interval     string    `json:"interval"`
	SyncOnCommit bool      `json:"sync_on_commit"`
	LastUpdate   time.Time `json:"last_update"`
	LastError    string    `json:"last_error,omitempty"`
	PublicKey    string    `json:"public_key,omitempty"`
}

// ---------------------------------------------------------------------------------------------
// Actions (runs, jobs, logs, variables, secrets)
// ---------------------------------------------------------------------------------------------

type Run struct {
	ID           int64     `json:"id"`
	Index        int64     `json:"index"` // run number in the repo
	WorkflowID   string    `json:"workflow_id"`
	Title        string    `json:"title"`
	Event        string    `json:"event"`
	Ref          string    `json:"ref"` // prettyref (branch or tag)
	SHA          string    `json:"sha"`
	Status       string    `json:"status"` // as Forgejo reports: waiting|running|success|failure|cancelled|skipped|blocked
	NeedApproval bool      `json:"need_approval"`
	Actor        Person    `json:"actor"`
	StartedAt    time.Time `json:"started_at"`
	StoppedAt    time.Time `json:"stopped_at"`
	HTMLURL      string    `json:"html_url"`
}

type RunQuery struct {
	Status  string
	Event   string
	Ref     string
	HeadSHA string
}

type Job struct {
	ID     int64    `json:"id"`
	Name   string   `json:"name"`
	Status string   `json:"status"`
	RunsOn []string `json:"runs_on"`
	Needs  []string `json:"needs,omitempty"`
}

// Logs is a bounded log excerpt (the tail is kept when cut).
type Logs struct {
	Content   string `json:"content"`
	Truncated bool   `json:"truncated"`
}

type Variable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ---------------------------------------------------------------------------------------------
// Interfaces (what other packages depend on). *Service implements Core.
// ---------------------------------------------------------------------------------------------

// Repos: organizations and repositories.
type Repos interface {
	EnsureOrg(ctx context.Context, slug string) error
	GetRepo(ctx context.Context, r RepoRef) (*Repository, error) // NotFound error if absent
	EnsureRepo(ctx context.Context, r RepoRef, spec RepoCreate) (*Repository, error)
	PatchRepo(ctx context.Context, r RepoRef, p RepoPatch) (*Repository, error)
	Migrate(ctx context.Context, spec MigrateSpec) (*Repository, error)
	UserExists(ctx context.Context, login string) (bool, error)
}

// Content: branches, tags, commits, tree, blobs, compare.
type Content interface {
	ListBranches(ctx context.Context, r RepoRef, p Page) (List[Branch], error)
	GetBranch(ctx context.Context, r RepoRef, name string) (*Branch, error)
	CreateBranch(ctx context.Context, r RepoRef, name, from string) (*Branch, error)
	DeleteBranch(ctx context.Context, r RepoRef, name string) error
	ListTags(ctx context.Context, r RepoRef, p Page) (List[Tag], error)
	CreateTag(ctx context.Context, r RepoRef, name, target, message string) (*Tag, error)
	DeleteTag(ctx context.Context, r RepoRef, name string) error
	ListCommits(ctx context.Context, r RepoRef, q CommitQuery, p Page) (List[Commit], error)
	GetCommit(ctx context.Context, r RepoRef, sha string) (*Commit, error)
	CommitDiff(ctx context.Context, r RepoRef, sha string) (*Diff, error)
	// ListTree lists one directory of ref (dir "" = root). Not recursive.
	ListTree(ctx context.Context, r RepoRef, ref, dir string, p Page) (List[TreeEntry], error)
	// GetFile returns the file at path@ref (content bounded by MaxBlobBytes).
	GetFile(ctx context.Context, r RepoRef, ref, path string) (*Blob, error)
	GetBlob(ctx context.Context, r RepoRef, sha string) (*Blob, error)
	Compare(ctx context.Context, r RepoRef, base, head string) (*Compare, error)
}

// Pulls: pull requests, reviews, comments, merge, checks.
type Pulls interface {
	ListPulls(ctx context.Context, r RepoRef, q PullQuery, p Page) (List[Pull], error)
	GetPull(ctx context.Context, r RepoRef, n int) (*Pull, error)
	CreatePull(ctx context.Context, r RepoRef, in PullCreate) (*Pull, error)
	PatchPull(ctx context.Context, r RepoRef, n int, in PullPatch) (*Pull, error)
	PullDiff(ctx context.Context, r RepoRef, n int) (*Diff, error)
	PullCommits(ctx context.Context, r RepoRef, n int, p Page) (List[Commit], error)
	UpdatePullBranch(ctx context.Context, r RepoRef, n int) error
	RequestReviewers(ctx context.Context, r RepoRef, n int, users, teams []string) error
	ListReviews(ctx context.Context, r RepoRef, n int) ([]Review, error)
	CreateReview(ctx context.Context, r RepoRef, n int, in ReviewCreate) (*Review, error)
	ListComments(ctx context.Context, r RepoRef, n int, p Page) (List[Comment], error)
	CreateComment(ctx context.Context, r RepoRef, n int, body string) (*Comment, error)
	MergePull(ctx context.Context, r RepoRef, n int, in MergeRequest) (*MergeResult, error)
	CancelAutoMerge(ctx context.Context, r RepoRef, n int) error
	ListChecks(ctx context.Context, r RepoRef, ref string) (*CheckSet, error)
	SetCheck(ctx context.Context, r RepoRef, sha string, in CheckInput) (*Check, error)
}

// Protections: branch protection rules (A4 is the main caller).
type Protections interface {
	ListProtections(ctx context.Context, r RepoRef) ([]Protection, error)
	GetProtection(ctx context.Context, r RepoRef, rule string) (*Protection, error) // NotFound if absent
	// UpsertProtection creates the rule or edits it if it exists (idempotent).
	UpsertProtection(ctx context.Context, r RepoRef, spec ProtectionSpec) (*Protection, error)
	DeleteProtection(ctx context.Context, r RepoRef, rule string) error
}

// Teams: team projection of Capsule roles (A2).
type Teams interface {
	EnsureTeam(ctx context.Context, org string, spec TeamSpec) (*Team, error)
	AddTeamRepo(ctx context.Context, teamID int64, r RepoRef) error
	TeamMembers(ctx context.Context, teamID int64) ([]string, error)
	AddTeamMember(ctx context.Context, teamID int64, login string) error
	RemoveTeamMember(ctx context.Context, teamID int64, login string) error
}

// Hooks, SSH keys and push mirrors.
type Hooks interface {
	ListHooks(ctx context.Context, r RepoRef) ([]Hook, error)
	// EnsureHook finds the hook with the same URL (PATCH, keeps secret in sync) or creates it.
	EnsureHook(ctx context.Context, r RepoRef, spec HookSpec) (*Hook, error)
	DeleteHook(ctx context.Context, r RepoRef, id int64) error
}

type Keys interface {
	// SSH keys act on the Sudo user (ctx must carry WithActor).
	ListSSHKeys(ctx context.Context) ([]SSHKey, error)
	AddSSHKey(ctx context.Context, title, key string, readOnly bool) (*SSHKey, error)
	DeleteSSHKey(ctx context.Context, id int64) error
}

type Mirrors interface {
	ListPushMirrors(ctx context.Context, r RepoRef) ([]PushMirror, error)
	AddPushMirror(ctx context.Context, r RepoRef, spec PushMirrorSpec) (*PushMirror, error)
	DeletePushMirror(ctx context.Context, r RepoRef, remoteName string) error
	SyncPushMirrors(ctx context.Context, r RepoRef) error
}

// Actions: runs, jobs, logs, dispatch, variables and secrets (org when r.Repo == "").
type Actions interface {
	ListRuns(ctx context.Context, r RepoRef, q RunQuery, p Page) (List[Run], error)
	GetRun(ctx context.Context, r RepoRef, id int64) (*Run, error)
	ListJobs(ctx context.Context, r RepoRef, runID int64) ([]Job, error)
	JobLogs(ctx context.Context, r RepoRef, jobID int64, maxBytes int) (*Logs, error)
	CancelRun(ctx context.Context, r RepoRef, id int64) error
	DispatchWorkflow(ctx context.Context, r RepoRef, workflow, ref string, inputs map[string]string) error
	ListVariables(ctx context.Context, r RepoRef) ([]Variable, error)
	SetVariable(ctx context.Context, r RepoRef, name, value string) error
	DeleteVariable(ctx context.Context, r RepoRef, name string) error
	SetSecret(ctx context.Context, r RepoRef, name, value string) error // write-only
	DeleteSecret(ctx context.Context, r RepoRef, name string) error
}

// Maintenance: cache invalidation (call from the inbound webhook, A5) and health.
type Maintenance interface {
	// InvalidateRepo drops cached lists (branches, pulls, runs, checks...) of the repo.
	// SHA-addressed objects (tree, blob, commit, diff) are immutable and stay cached.
	InvalidateRepo(ctx context.Context, r RepoRef) error
	// Ping checks that Forgejo answers (GET /version) and reports the breaker state.
	Ping(ctx context.Context) error
	Enabled() bool
}

// Core is the whole gitcore surface. Depend on the narrowest sub-interface you need.
type Core interface {
	Repos
	Content
	Pulls
	Protections
	Teams
	Hooks
	Keys
	Mirrors
	Actions
	Maintenance
}

// Cache is the (existing) Redis cache contract; domain.CacheStore satisfies it. Any Get error
// is a miss. nil disables caching.
type Cache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, ttlSeconds int) error
	Del(ctx context.Context, key string) error
}
