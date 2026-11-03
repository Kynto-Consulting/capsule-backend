package gitsource

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// signatureHeaders are the accepted HMAC-SHA256 signature headers.
var signatureHeaders = []string{
	"X-Hub-Signature-256", // GitHub, also Forgejo/Gitea
	"X-Forgejo-Signature",
	"X-Gitea-Signature",
	"X-Capsule-Signature", // generic
}

// VerifySignature checks an HMAC-SHA256 signature of body in constant time.
// Values may be hex or "sha256=<hex>". An empty secret never verifies.
func VerifySignature(h http.Header, body []byte, secret string) bool {
	if secret == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := mac.Sum(nil)
	ok := false
	for _, name := range signatureHeaders {
		v := strings.TrimSpace(h.Get(name))
		if v == "" {
			continue
		}
		v = strings.TrimPrefix(v, "sha256=")
		got, err := hex.DecodeString(v)
		if err != nil {
			continue
		}
		// no early return: evaluate every present header the same way
		if hmac.Equal(got, want) {
			ok = true
		}
	}
	return ok
}

// Sign returns the "sha256=<hex>" signature of body (for tests and tooling).
func Sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Event kinds produced by ParseEvent.
const (
	EventPush        = "push"
	EventPullRequest = "pull_request"
	EventIgnored     = "ignored"

	// Added by package A5 (product events). They never trigger deploys or previews.
	EventReview        = "pull_request_review" // a review was submitted (approved|changes_requested|commented)
	EventStatus        = "status"              // a commit status changed
	EventWorkflowRun   = "workflow_run"        // a CI run changed state
	EventBranchCreated = "branch_created"      // create event, ref_type=branch
	EventBranchDeleted = "branch_deleted"      // delete event, ref_type=branch
)

// Normalized review states of Event.ReviewState.
const (
	ReviewApproved         = "approved"
	ReviewChangesRequested = "changes_requested"
	ReviewCommented        = "commented"
)

// Event is the provider-neutral view of a webhook delivery.
type Event struct {
	Kind      string
	Branch    string // push: pushed branch; pull_request: head branch
	SHA       string // push: new head; pull_request: head sha
	Actor     string
	Message   string
	CommitURL string
	RepoURLs  []string // repository URLs the payload advertises (clone/html)
	Deleted   bool     // push of a branch deletion

	PR       int
	Action   string // opened | reopened | synchronize | closed (normalized)
	Merged   bool
	PRURL    string
	BaseRef  string
	HeadFork bool // head repository differs from base repository
	HeadRepo string
	BaseRepo string
	Provider string

	// ---- A5 additions (all optional; zero for the legacy push/pull_request consumers) ----
	DeliveryID string // X-Forgejo-Delivery / X-Gitea-Delivery / X-GitHub-Delivery ("" when absent)
	RawEvent   string // the event name as the sender announced it
	Before     string // push: previous head
	Title      string // pull_request: title
	PRAuthor   string // pull_request: author login
	// pull_request actions beyond the legacy four: "edited" | "review_requested". For "edited",
	// TitleFrom carries the previous title (Forgejo "changes.title.from") when known.
	TitleFrom         string
	RequestedReviewer string // review_requested: login of the requested reviewer
	// EventReview
	ReviewState string // approved | changes_requested | commented
	ReviewBody  string
	Reviewer    string
	// EventStatus
	StatusContext string
	StatusState   string // pending | success | failure | error
	StatusURL     string
	StatusDesc    string
	// EventWorkflowRun
	RunID         string
	RunName       string
	RunStatus     string // as announced (completed, success, failure, ...)
	RunConclusion string // success | failure | cancelled | ... ("" when unknown)
	RunURL        string
	RunWorkflow   string
	RunCompleted  bool // the run reached a final state
}

// DeliveryID returns the unique delivery id announced by the sender, or "".
func DeliveryID(h http.Header) string {
	for _, k := range []string{"X-Forgejo-Delivery", "X-Gitea-Delivery", "X-GitHub-Delivery"} {
		if v := strings.TrimSpace(h.Get(k)); v != "" {
			if len(v) > 200 {
				v = v[:200]
			}
			return v
		}
	}
	return ""
}

type ghRepo struct {
	FullName string `json:"full_name"`
	CloneURL string `json:"clone_url"`
	HTMLURL  string `json:"html_url"`
	SSHURL   string `json:"ssh_url"`
}

type ghPayload struct {
	Ref     string `json:"ref"`
	RefType string `json:"ref_type"` // create/delete events: branch | tag
	Before  string `json:"before"`
	After   string `json:"after"`
	Deleted bool   `json:"deleted"`
	Action  string `json:"action"`
	Number  int    `json:"number"`
	// review events (Gitea/Forgejo: review.type approved|rejected|comment; GitHub: review.state)
	Review *struct {
		Type    string `json:"type"`
		State   string `json:"state"`
		Content string `json:"content"`
		Body    string `json:"body"`
		User    struct {
			Login string `json:"login"`
		} `json:"user"`
	} `json:"review"`
	RequestedReviewer *struct {
		Login string `json:"login"`
	} `json:"requested_reviewer"`
	Changes *struct {
		Title *struct {
			From string `json:"from"`
		} `json:"title"`
	} `json:"changes"`
	// status events (GitHub shape)
	State       string `json:"state"`
	SHA         string `json:"sha"`
	Context     string `json:"context"`
	Description string `json:"description"`
	TargetURL   string `json:"target_url"`
	Pusher      struct {
		Login    string `json:"login"`
		Name     string `json:"name"`
		Username string `json:"username"`
	} `json:"pusher"`
	Sender struct {
		Login    string `json:"login"`
		Username string `json:"username"`
	} `json:"sender"`
	HeadCommit struct {
		ID      string `json:"id"`
		Message string `json:"message"`
		URL     string `json:"url"`
	} `json:"head_commit"`
	Repository  ghRepo `json:"repository"`
	PullRequest *struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		HTMLURL string `json:"html_url"`
		Merged  bool   `json:"merged"`
		User    struct {
			Login string `json:"login"`
		} `json:"user"`
		Head struct {
			Ref  string `json:"ref"`
			SHA  string `json:"sha"`
			Repo ghRepo `json:"repo"`
		} `json:"head"`
		Base struct {
			Ref  string `json:"ref"`
			Repo ghRepo `json:"repo"`
		} `json:"base"`
	} `json:"pull_request"`
}

// ParseEvent decodes a (signature-verified) webhook body. Unknown or
// irrelevant events yield Kind == EventIgnored with a nil error.
func ParseEvent(h http.Header, body []byte) (*Event, error) {
	var p ghPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, errors.New("invalid payload")
	}
	provider := "generic"
	name := ""
	switch {
	case h.Get("X-GitHub-Event") != "":
		provider, name = "github", h.Get("X-GitHub-Event")
	case h.Get("X-Forgejo-Event") != "":
		provider, name = "forgejo", h.Get("X-Forgejo-Event")
	case h.Get("X-Gitea-Event") != "":
		provider, name = "gitea", h.Get("X-Gitea-Event")
	case h.Get("X-Capsule-Event") != "":
		name = h.Get("X-Capsule-Event")
	default:
		if p.PullRequest != nil {
			name = "pull_request"
		} else if p.Ref != "" {
			name = "push"
		}
	}
	ev := &Event{Kind: EventIgnored, Provider: provider, DeliveryID: DeliveryID(h), RawEvent: name}
	lname := strings.ToLower(name)
	// Gitea/Forgejo announce review events as "pull_request_approved" etc. and also send the
	// finer-grained "...-Event-Type" header; both are accepted. Verified on v15.0.11 (fixtures in testdata/forgejo_v15.0.11):
	// X-Forgejo-Event is pull_request_approved|pull_request_rejected|pull_request_comment, the Event-Type
	// is pull_request_review_approved|rejected|comment, and a plain PR conversation comment is
	// "issue_comment" (ignored here).
	evType := strings.ToLower(firstNonEmpty(h.Get("X-Forgejo-Event-Type"), h.Get("X-Gitea-Event-Type")))
	switch lname {
	case "push":
		const pre = "refs/heads/"
		if !strings.HasPrefix(p.Ref, pre) {
			return ev, nil // tags and other refs
		}
		ev.Kind = EventPush
		ev.Branch = strings.TrimPrefix(p.Ref, pre)
		ev.SHA = firstNonEmpty(p.After, p.HeadCommit.ID)
		ev.Before = p.Before
		ev.Deleted = p.Deleted || strings.Trim(ev.SHA, "0") == ""
		ev.Message = p.HeadCommit.Message
		ev.CommitURL = p.HeadCommit.URL
		ev.Actor = firstNonEmpty(p.Pusher.Login, p.Pusher.Username, p.Sender.Login, p.Sender.Username, p.Pusher.Name)
		ev.RepoURLs = repoURLs(p.Repository)
		return ev, nil
	case "pull_request":
		if p.PullRequest == nil {
			return ev, nil
		}
		fillPR(ev, &p)
		switch strings.ToLower(p.Action) {
		case "opened":
			ev.Action = "opened"
		case "reopened":
			ev.Action = "reopened"
		case "synchronize", "synchronized":
			ev.Action = "synchronize"
		case "closed":
			ev.Action = "closed"
		case "edited":
			ev.Action = "edited"
			if p.Changes != nil && p.Changes.Title != nil {
				ev.TitleFrom = p.Changes.Title.From
			}
		case "review_requested":
			ev.Action = "review_requested"
			if p.RequestedReviewer != nil {
				ev.RequestedReviewer = p.RequestedReviewer.Login
			}
		case "reviewed", "review_approved", "review_rejected", "review_comment", "submitted":
			return parseReview(ev, &p, lname, evType), nil
		default:
			ev.Kind = EventIgnored
		}
		return ev, nil
	case "create", "delete":
		if p.RefType != "branch" || p.Ref == "" {
			return ev, nil // tags and anything else
		}
		ev.Kind = EventBranchCreated
		if lname == "delete" {
			ev.Kind = EventBranchDeleted
		}
		ev.Branch = strings.TrimPrefix(p.Ref, "refs/heads/")
		ev.Actor = firstNonEmpty(p.Sender.Login, p.Sender.Username)
		ev.RepoURLs = repoURLs(p.Repository)
		return ev, nil
	case "pull_request_review", "pull_request_approved", "pull_request_rejected", "pull_request_comment",
		"pull_request_review_approved", "pull_request_review_rejected", "pull_request_review_comment":
		if p.PullRequest == nil {
			return ev, nil
		}
		fillPR(ev, &p)
		return parseReview(ev, &p, lname, evType), nil
	case "status":
		state := strings.ToLower(p.State)
		switch state {
		case "success", "failure", "error":
		default:
			return ev, nil // pending (or unknown): not a final state
		}
		ev.Kind = EventStatus
		ev.SHA = p.SHA
		ev.StatusContext = p.Context
		ev.StatusState = state
		ev.StatusURL = p.TargetURL
		ev.StatusDesc = p.Description
		ev.Actor = firstNonEmpty(p.Sender.Login, p.Sender.Username)
		ev.RepoURLs = repoURLs(p.Repository)
		return ev, nil
	case "workflow_run", "action_run", "action_run_failure", "action_run_recover", "action_run_success":
		return parseRun(ev, body, lname), nil
	}
	return ev, nil
}

// fillPR copies the pull request block of a payload into ev (shared by pull_request and review
// events).
func fillPR(ev *Event, p *ghPayload) {
	pr := p.PullRequest
	ev.Kind = EventPullRequest
	ev.PR = firstPositive(p.Number, pr.Number)
	ev.Branch = pr.Head.Ref
	ev.SHA = pr.Head.SHA
	ev.PRURL = pr.HTMLURL
	ev.BaseRef = pr.Base.Ref
	ev.Merged = pr.Merged
	ev.Title = pr.Title
	ev.PRAuthor = pr.User.Login
	ev.Actor = firstNonEmpty(p.Sender.Login, p.Sender.Username)
	ev.HeadRepo, ev.BaseRepo = strings.ToLower(pr.Head.Repo.FullName), strings.ToLower(pr.Base.Repo.FullName)
	ev.HeadFork = ev.HeadRepo == "" || ev.HeadRepo != ev.BaseRepo
	ev.RepoURLs = repoURLs(pr.Base.Repo)
	if len(ev.RepoURLs) == 0 {
		ev.RepoURLs = repoURLs(p.Repository)
	}
}

// parseReview turns a review payload into an EventReview. A "pull_request_comment" without a
// review block is a plain conversation comment and stays ignored. ev already carries the PR.
func parseReview(ev *Event, p *ghPayload, lname, evType string) *Event {
	if p.Review == nil {
		ev.Kind = EventIgnored
		return ev
	}
	state := ""
	for _, s := range []string{lname, evType} {
		switch {
		case strings.HasSuffix(s, "approved"):
			state = ReviewApproved
		case strings.HasSuffix(s, "rejected"):
			state = ReviewChangesRequested
		case s == "pull_request_review_comment": // real v15.0.11: Event-Type of a COMMENT review
			state = ReviewCommented
		}
		if state != "" {
			break
		}
	}
	if state == "" {
		switch strings.ToLower(firstNonEmpty(p.Review.Type, p.Review.State)) {
		case "approved", "approve":
			state = ReviewApproved
		case "rejected", "reject", "changes_requested", "request_changes":
			state = ReviewChangesRequested
		case "comment", "commented":
			state = ReviewCommented
		}
	}
	if state == "" {
		ev.Kind = EventIgnored
		return ev
	}
	ev.Kind = EventReview
	ev.ReviewState = state
	ev.ReviewBody = firstNonEmpty(p.Review.Content, p.Review.Body)
	ev.Reviewer = firstNonEmpty(p.Review.User.Login, ev.Actor)
	return ev
}

// parseRun reads CI run events. GitHub shape: {"action":"completed","workflow_run":{...}}.
// Forgejo shape (?): header action_run_failure|action_run_recover|action_run_success and a run
// object under "run"/"action_run" — field names are NOT confirmed against v15.0.11, so every
// field is read tolerantly and only final states produce an event.
func parseRun(ev *Event, body []byte, lname string) *Event {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return ev
	}
	run := firstMap(m, "workflow_run", "action_run", "run")
	if run == nil {
		return ev
	}
	conclusion := strings.ToLower(str(run["conclusion"]))
	completed := false
	switch lname {
	case "action_run_failure":
		completed, conclusion = true, firstNonEmpty(conclusion, "failure")
	case "action_run_success", "action_run_recover":
		completed, conclusion = true, firstNonEmpty(conclusion, "success")
	default:
		action := strings.ToLower(str(m["action"]))
		status := strings.ToLower(str(run["status"]))
		switch {
		case action == "completed" || status == "completed":
			completed = true
		case status == "success" || status == "failure" || status == "cancelled" || status == "skipped":
			completed, conclusion = true, firstNonEmpty(conclusion, status)
		}
	}
	if !completed {
		return ev
	}
	ev.Kind = EventWorkflowRun
	ev.RunID = firstNonEmpty(str(run["id"]), str(run["index"]))
	ev.RunName = firstNonEmpty(str(run["name"]), str(run["title"]), str(run["display_title"]))
	ev.RunStatus = str(run["status"])
	ev.RunConclusion = conclusion
	ev.RunCompleted = true
	ev.RunURL = firstNonEmpty(str(run["html_url"]), str(run["url"]))
	ev.RunWorkflow = firstNonEmpty(str(run["workflow_id"]), str(run["path"]))
	ev.SHA = firstNonEmpty(str(run["head_sha"]), str(run["commit_sha"]), str(run["sha"]))
	ev.Branch = strings.TrimPrefix(firstNonEmpty(str(run["head_branch"]), str(run["ref"]), str(run["prettyref"])), "refs/heads/")
	if sender, ok := m["sender"].(map[string]any); ok {
		ev.Actor = firstNonEmpty(str(sender["login"]), str(sender["username"]))
	}
	if repo, ok := m["repository"].(map[string]any); ok {
		for _, k := range []string{"clone_url", "html_url", "ssh_url"} {
			if u := str(repo[k]); u != "" {
				ev.RepoURLs = append(ev.RepoURLs, u)
			}
		}
	}
	return ev
}

func firstMap(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		if v, ok := m[k].(map[string]any); ok {
			return v
		}
	}
	return nil
}

// str renders a JSON scalar as a string ("" for anything else; numbers without exponent).
func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	}
	return ""
}

func repoURLs(r ghRepo) []string {
	var out []string
	for _, u := range []string{r.CloneURL, r.HTMLURL, r.SSHURL} {
		if u != "" {
			out = append(out, u)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstPositive(vals ...int) int {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return 0
}

// RepoKey normalizes a repository URL (https or ssh, scp-like git@host:path)
// to "host/owner/repo" for comparison; "" when unparsable.
func RepoKey(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		// scp-like: git@host:owner/repo.git
		if i := strings.Index(raw, "@"); i >= 0 {
			raw = raw[i+1:]
		}
		raw = "ssh://" + strings.Replace(raw, ":", "/", 1)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	path := strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
	return strings.ToLower(u.Hostname()) + "/" + strings.ToLower(path)
}

// SameRepo reports whether any advertised URL points at the configured repo.
// With no advertised URLs it returns true (the HMAC already authenticates the sender).
func SameRepo(configured string, advertised []string) bool {
	if len(advertised) == 0 {
		return true
	}
	want := RepoKey(configured)
	if want == "" {
		return false
	}
	for _, a := range advertised {
		if RepoKey(a) == want {
			return true
		}
	}
	return false
}
