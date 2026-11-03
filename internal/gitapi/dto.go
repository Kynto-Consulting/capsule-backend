package gitapi

import (
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// ---- pull requests --------------------------------------------------------------------------

// PullOut is the API schema Pull. Mergeable/ChecksState are nil in list responses (computing them
// costs several upstream calls per pull request); the detail endpoint always fills them.
type PullOut struct {
	Number      int              `json:"number"`
	Title       string           `json:"title"`
	Body        string           `json:"body"`
	State       string           `json:"state"`
	Draft       bool             `json:"draft"`
	Head        string           `json:"head"`
	Base        string           `json:"base"`
	HeadSHA     string           `json:"head_sha"`
	Author      gitcore.Person   `json:"author"`
	Reviewers   []gitcore.Person `json:"reviewers"`
	Labels      []string         `json:"labels"`
	Mergeable   *Mergeability    `json:"mergeable,omitempty"`
	ChecksState string           `json:"checks_state,omitempty"`
	AutoMerge   any              `json:"auto_merge"`
	PreviewURL  *string          `json:"preview_url"`
	HTMLURL     string           `json:"html_url"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
	MergedAt    *time.Time       `json:"merged_at"`
	// Legacy aliases kept for the first consumers of GET .../git/pulls (CLI and dashboard).
	HeadRef string `json:"head_ref"`
	BaseRef string `json:"base_ref"`
	URL     string `json:"url"`
}

// PullDecorator lets other packages fill fields they own (auto_merge from B8, preview_url...).
type PullDecorator func(ref gitcore.RepoRef, p gitcore.Pull, out *PullOut)

// ToPull maps a gitcore pull request to the API shape.
func ToPull(p gitcore.Pull) PullOut {
	state := string(p.State)
	if p.Merged {
		state = string(gitcore.PullMerged)
	}
	reviewers := p.Reviewers
	if reviewers == nil {
		reviewers = []gitcore.Person{}
	}
	labels := p.Labels
	if labels == nil {
		labels = []string{}
	}
	html := p.HTMLURL
	if html != "" && !strings.HasSuffix(html, "/files") {
		html = strings.TrimRight(html, "/") + "/files"
	}
	return PullOut{
		Number: p.Number, Title: p.Title, Body: p.Body, State: state, Draft: p.Draft,
		Head: p.Head, Base: p.Base, HeadSHA: p.HeadSHA, Author: p.Author, Reviewers: reviewers,
		Labels: labels, HTMLURL: html, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, MergedAt: p.MergedAt,
		HeadRef: p.Head, BaseRef: p.Base, URL: p.HTMLURL,
	}
}

// ---- branches -------------------------------------------------------------------------------

// BranchOut is the API schema Branch (ahead/behind are not computed: one compare per branch is too
// expensive for a list; the compare endpoint gives them per pair).
type BranchOut struct {
	Name             string    `json:"name"`
	SHA              string    `json:"sha"`
	Protected        bool      `json:"protected"`
	ProtectionRuleID *string   `json:"protection_rule_id"`
	ProtectionRule   string    `json:"protection_rule,omitempty"`
	Default          bool      `json:"default"`
	UpdatedAt        time.Time `json:"updated_at"`
	Author           string    `json:"author,omitempty"`
}

func ToBranch(b gitcore.Branch) BranchOut {
	return BranchOut{Name: b.Name, SHA: b.SHA, Protected: b.Protected, ProtectionRule: b.ProtectionRule,
		Default: b.Default, UpdatedAt: b.UpdatedAt, Author: b.Author}
}

// ---- reviews, comments ----------------------------------------------------------------------

type ReviewOut struct {
	ID          int64          `json:"id"`
	State       string         `json:"state"`
	Body        string         `json:"body"`
	Author      gitcore.Person `json:"author"`
	CommitSHA   string         `json:"commit_sha"`
	Stale       bool           `json:"stale"`
	SubmittedAt time.Time      `json:"submitted_at"`
}

// ToReview maps a review; ok is false for pending (unsubmitted) reviews, which the API hides.
func ToReview(r gitcore.Review) (ReviewOut, bool) {
	if r.State == "pending" {
		return ReviewOut{}, false
	}
	return ReviewOut{ID: r.ID, State: r.State, Body: r.Body, Author: r.Author, CommitSHA: r.CommitSHA,
		Stale: r.Stale, SubmittedAt: r.SubmittedAt}, true
}

// ReviewListOut is the API schema ReviewList.
type ReviewListOut struct {
	Items            []ReviewOut `json:"items"`
	Approvals        int         `json:"approvals"`
	RequiredApproval int         `json:"required_approvals"`
	CodeOwnerPending []string    `json:"code_owner_pending"`
}

// ---- checks ---------------------------------------------------------------------------------

type CheckOut struct {
	Context     string             `json:"context"`
	State       gitcore.CheckState `json:"state"`
	TargetURL   string             `json:"target_url,omitempty"`
	Description string             `json:"description,omitempty"`
	Required    bool               `json:"required"`
	Source      string             `json:"source"`
	UpdatedAt   time.Time          `json:"updated_at"`
}

type CheckListOut struct {
	State string     `json:"state"`
	Items []CheckOut `json:"items"`
}

// CheckSource classifies a status context for the "source" enum.
func CheckSource(context string) string {
	switch {
	case strings.HasPrefix(context, "capsule/security"):
		return "security"
	case strings.HasPrefix(context, "capsule/"):
		return "capsule"
	case strings.Contains(context, " / ") || strings.HasSuffix(context, ")") && strings.Contains(context, "("):
		return "actions" // Forgejo Actions: "<workflow> / <job> (<event>)"
	}
	return "external"
}

// ToCheckList maps a CheckSet; required marks contexts matched by the rule's required contexts.
func ToCheckList(cs *gitcore.CheckSet, rule *gitcore.ProtectionSpec) CheckListOut {
	out := CheckListOut{State: CombinedState(cs), Items: []CheckOut{}}
	if cs == nil {
		return out
	}
	for _, c := range cs.Items {
		req := false
		if rule != nil && rule.EnableStatusCheck {
			for _, pat := range rule.StatusCheckContexts {
				if MatchGlob(strings.TrimSpace(pat), c.Context) {
					req = true
					break
				}
			}
		}
		out.Items = append(out.Items, CheckOut{Context: c.Context, State: c.State, TargetURL: c.TargetURL,
			Description: c.Description, Required: req, Source: CheckSource(c.Context), UpdatedAt: c.UpdatedAt})
	}
	return out
}

// ---- blobs ----------------------------------------------------------------------------------

type BlobOut struct {
	gitcore.Blob
	Language string `json:"language,omitempty"`
}

var langByExt = map[string]string{
	".go": "go", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
	".ts": "typescript", ".tsx": "typescript", ".py": "python", ".rb": "ruby", ".rs": "rust",
	".java": "java", ".kt": "kotlin", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
	".cs": "csharp", ".php": "php", ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".sql": "sql",
	".json": "json", ".yml": "yaml", ".yaml": "yaml", ".toml": "toml", ".md": "markdown", ".html": "html",
	".htm": "html", ".css": "css", ".scss": "scss", ".xml": "xml", ".svg": "xml", ".tf": "hcl",
	".dockerfile": "dockerfile", ".swift": "swift", ".lua": "lua", ".vue": "vue",
}

// LanguageOf guesses a highlight language from a file path ("" when unknown).
func LanguageOf(p string) string {
	base := strings.ToLower(path.Base(p))
	switch base {
	case "dockerfile":
		return "dockerfile"
	case "makefile":
		return "makefile"
	}
	return langByExt[path.Ext(base)]
}

func ToBlob(b *gitcore.Blob, filePath string) BlobOut {
	if b.Path == "" {
		b.Path = filePath
	}
	return BlobOut{Blob: *b, Language: LanguageOf(b.Path)}
}

// ---- Actions --------------------------------------------------------------------------------

// RunStatus maps Forgejo's run status to the API enum.
func RunStatus(status string, needApproval bool) string {
	if needApproval {
		return "waiting_approval"
	}
	switch strings.ToLower(status) {
	case "waiting", "queued", "pending":
		return "queued"
	case "running":
		return "running"
	case "success":
		return "success"
	case "failure", "failed", "error":
		return "failure"
	case "blocked":
		return "waiting_approval"
	case "cancelled", "canceled", "skipped":
		return "cancelled"
	}
	return "queued"
}

// ForgejoRunStatus is the inverse used to translate the ?status= filter (ok=false: filter client side).
func ForgejoRunStatus(api string) (string, bool) {
	switch api {
	case "queued":
		return "waiting", true
	case "running", "success", "failure", "cancelled":
		return api, true
	}
	return "", false
}

// JobStatus maps a job status to the API enum.
func JobStatus(status string) string {
	switch strings.ToLower(status) {
	case "waiting", "queued", "pending", "blocked":
		return "queued"
	case "running":
		return "running"
	case "success":
		return "success"
	case "failure", "failed", "error":
		return "failure"
	case "cancelled", "canceled":
		return "cancelled"
	case "skipped":
		return "skipped"
	}
	return "queued"
}

// JobFinished reports whether a job status is terminal.
func JobFinished(status string) bool {
	switch JobStatus(status) {
	case "success", "failure", "cancelled", "skipped":
		return true
	}
	return false
}

// RunStepOut is one step of a job as the Forgejo UI lists it (including the runner's "Set up job" and
// "Complete job" steps).
type RunStepOut struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Duration string `json:"duration,omitempty"`
}

type RunJobOut struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Status       string   `json:"status"`
	RunnerLabels []string `json:"runner_labels"`
	// Steps come from the Forgejo web session (omitted when it is not configured or fails).
	Steps []RunStepOut `json:"steps,omitempty"`
}

type RunOut struct {
	ID        string         `json:"id"`
	Workflow  string         `json:"workflow"`
	Branch    string         `json:"branch"`
	SHA       string         `json:"sha"`
	Event     string         `json:"event"`
	Status    string         `json:"status"`
	Actor     gitcore.Person `json:"actor"`
	PR        *int           `json:"pr"`
	CreatedAt time.Time      `json:"created_at"`
	HTMLURL   string         `json:"html_url"`
	Jobs      []RunJobOut    `json:"jobs,omitempty"`
	Number    int64          `json:"number"`
	Title     string         `json:"title,omitempty"`
	// JobsUnavailable is why jobs are absent: the Forgejo web session is not configured or not allowed.
	JobsUnavailable string `json:"jobs_unavailable,omitempty"`
}

// ToRun maps a run. A run of a pull request (ref "pull/N/...") reports its number in pr.
func ToRun(r gitcore.Run) RunOut {
	out := RunOut{ID: strconv.FormatInt(r.ID, 10), Workflow: r.WorkflowID, Branch: r.Ref, SHA: r.SHA, Event: r.Event,
		Status: RunStatus(r.Status, r.NeedApproval), Actor: r.Actor, CreatedAt: r.StartedAt, HTMLURL: r.HTMLURL,
		Number: r.Index, Title: r.Title}
	if strings.HasPrefix(r.Ref, "pull/") {
		parts := strings.Split(r.Ref, "/")
		if len(parts) > 1 {
			if n, err := strconv.Atoi(parts[1]); err == nil {
				out.PR = &n
			}
		}
	}
	return out
}

func ToRunJobs(jobs []gitcore.Job) []RunJobOut {
	out := make([]RunJobOut, 0, len(jobs))
	for _, j := range jobs {
		labels := j.RunsOn
		if labels == nil {
			labels = []string{}
		}
		out = append(out, RunJobOut{ID: strconv.FormatInt(j.ID, 10), Name: j.Name, Status: JobStatus(j.Status), RunnerLabels: labels})
	}
	return out
}

// ---- misc -----------------------------------------------------------------------------------

// DeterministicID is a stable UUID for objects Forgejo identifies by number (activity entries).
func DeterministicID(parts ...string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("git-capsule/"+strings.Join(parts, "|"))).String()
}

// AttachSteps fills the steps of each job (by job id) from gitcore's per-job step lists.
func AttachSteps(jobs []RunJobOut, steps map[int64][]gitcore.JobStep) {
	for i := range jobs {
		id, err := strconv.ParseInt(jobs[i].ID, 10, 64)
		if err != nil {
			continue
		}
		for _, s := range steps[id] {
			jobs[i].Steps = append(jobs[i].Steps, RunStepOut{Name: s.Name, Status: JobStatus(s.Status), Duration: s.Duration})
		}
	}
}
