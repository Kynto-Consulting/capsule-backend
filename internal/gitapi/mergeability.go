package gitapi

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// Blocker codes (API.openapi.yaml, schema Mergeability).
const (
	BlockChecks     = "CHECKS_REQUIRED"
	BlockReviews    = "REVIEWS_REQUIRED"
	BlockCodeowner  = "CODEOWNER_REQUIRED"
	BlockConflicts  = "CONFLICTS"
	BlockOutOfDate  = "BRANCH_OUT_OF_DATE"
	BlockPolicy     = "POLICY_BLOCKED"
	BlockDraft      = "DRAFT"
	BlockSignature  = "SIGNATURE_REQUIRED"
	BlockApproval   = "APPROVAL_REQUIRED"
	maxSignedLookup = 100
)

// Blocker is one reason a pull request cannot be merged now.
type Blocker struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Mergeability is the API schema of the same name. Blockers is never null.
type Mergeability struct {
	CanMerge bool      `json:"can_merge"`
	Blockers []Blocker `json:"blockers"`
}

// Inputs is everything Evaluate needs; Assess gathers it from gitcore.
type Inputs struct {
	Pull       gitcore.Pull
	Rule       *gitcore.ProtectionSpec // protection rule of the base branch, nil = none
	Checks     *gitcore.CheckSet
	Reviews    []gitcore.Review
	BehindBase bool     // the head does not contain the base tip
	Unsigned   []string // short SHAs of unverified commits (only filled when the rule needs signatures)
	Extra      []Blocker
}

// Evaluate is the pure mergeability decision (table-tested). The order of the blockers is stable.
func Evaluate(in Inputs) Mergeability {
	out := Mergeability{Blockers: []Blocker{}}
	p := in.Pull
	if p.State != gitcore.PullOpen {
		return out // merged/closed: nothing to block, nothing to merge
	}
	add := func(code, format string, a ...any) {
		out.Blockers = append(out.Blockers, Blocker{Code: code, Message: fmt.Sprintf(format, a...)})
	}
	if p.Draft {
		add(BlockDraft, "the pull request is a draft; mark it ready for review first")
	}
	if !p.Mergeable {
		add(BlockConflicts, "the branch has conflicts with %s that must be resolved", p.Base)
	}
	if r := in.Rule; r != nil {
		if r.EnableStatusCheck {
			for _, msg := range missingChecks(r.StatusCheckContexts, in.Checks) {
				add(BlockChecks, "%s", msg)
			}
		}
		approvals, rejecters := countReviews(in.Reviews, *r)
		if r.RequiredApprovals > 0 && approvals < r.RequiredApprovals {
			add(BlockReviews, "%d of %d required approvals", approvals, r.RequiredApprovals)
		}
		if r.BlockOnRejectedReviews && len(rejecters) > 0 {
			add(BlockReviews, "changes requested by %s", strings.Join(rejecters, ", "))
		}
		if r.BlockOnOfficialReviewRequest && len(p.Reviewers) > 0 {
			names := make([]string, 0, len(p.Reviewers))
			for _, u := range p.Reviewers {
				names = append(names, u.Login)
			}
			add(BlockReviews, "awaiting review from %s", strings.Join(names, ", "))
		}
		if r.BlockOnOutdatedBranch && in.BehindBase {
			add(BlockOutOfDate, "the branch is behind %s; update it before merging", p.Base)
		}
		if r.RequireSignedCommits && len(in.Unsigned) > 0 {
			add(BlockSignature, "unsigned commits: %s", strings.Join(in.Unsigned, ", "))
		}
	}
	out.Blockers = append(out.Blockers, in.Extra...)
	out.CanMerge = len(out.Blockers) == 0
	return out
}

// missingChecks returns one message per required context (a glob) that is absent or not green.
func missingChecks(contexts []string, cs *gitcore.CheckSet) []string {
	var msgs []string
	for _, pat := range contexts {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		var matched []gitcore.Check
		if cs != nil {
			for _, c := range cs.Items {
				if MatchGlob(pat, c.Context) {
					matched = append(matched, c)
				}
			}
		}
		if len(matched) == 0 {
			msgs = append(msgs, fmt.Sprintf("required check %q has not reported yet", pat))
			continue
		}
		for _, c := range matched {
			switch c.State {
			case gitcore.CheckSuccess, gitcore.CheckSkipped:
			case gitcore.CheckPending:
				msgs = append(msgs, fmt.Sprintf("required check %q is still running", c.Context))
			default:
				msgs = append(msgs, fmt.Sprintf("required check %q failed", c.Context))
			}
		}
	}
	return msgs
}

// countReviews counts the qualifying approvals (latest decision per reviewer, official only, stale
// ones dropped when the rule ignores them) and lists reviewers whose latest decision is "changes".
func countReviews(reviews []gitcore.Review, r gitcore.ProtectionSpec) (approvals int, rejecters []string) {
	sorted := append([]gitcore.Review(nil), reviews...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	latest := map[string]gitcore.Review{}
	for _, rv := range sorted {
		switch rv.State {
		case "approved", "changes_requested", "dismissed":
			latest[rv.Author.Login] = rv
		}
	}
	logins := make([]string, 0, len(latest))
	for l := range latest {
		logins = append(logins, l)
	}
	sort.Strings(logins)
	for _, l := range logins {
		rv := latest[l]
		switch rv.State {
		case "approved":
			if rv.Official && !(r.IgnoreStaleApprovals && rv.Stale) {
				approvals++
			}
		case "changes_requested":
			if rv.Official {
				rejecters = append(rejecters, l)
			}
		}
	}
	return
}

// MatchRule picks the protection rule that applies to branch: an exact rule name wins, otherwise
// the longest matching glob (deterministic).
func MatchRule(rules []gitcore.Protection, branch string) *gitcore.ProtectionSpec {
	var best *gitcore.ProtectionSpec
	for i := range rules {
		name := rules[i].RuleName
		if name == branch {
			s := rules[i].ProtectionSpec
			return &s
		}
		if MatchGlob(name, branch) && (best == nil || len(name) > len(best.RuleName)) {
			s := rules[i].ProtectionSpec
			best = &s
		}
	}
	return best
}

// BlockerSource lets other packages add blockers (CODEOWNERS from B8, security policy from B7,
// environment approvals from A6). A source that errors makes the pull request unmergeable
// (fail closed, SPEC principle 4).
type BlockerSource func(ctx context.Context, ref gitcore.RepoRef, p gitcore.Pull) ([]Blocker, error)

var (
	srcMu   sync.RWMutex
	sources []BlockerSource
)

// RegisterBlockerSource adds a source (call from the Wire<Pkg> of the package that owns it).
func RegisterBlockerSource(s BlockerSource) {
	srcMu.Lock()
	sources = append(sources, s)
	srcMu.Unlock()
}

func extraBlockers(ctx context.Context, ref gitcore.RepoRef, p gitcore.Pull) []Blocker {
	srcMu.RLock()
	list := append([]BlockerSource(nil), sources...)
	srcMu.RUnlock()
	var out []Blocker
	for _, s := range list {
		bs, err := s(ctx, ref, p)
		if err != nil {
			out = append(out, Blocker{Code: BlockPolicy, Message: "a merge policy could not be evaluated; try again"})
			continue
		}
		out = append(out, bs...)
	}
	return out
}

// Assessment is the result of Assess.
type Assessment struct {
	Mergeability Mergeability
	Checks       *gitcore.CheckSet
	Rule         *gitcore.ProtectionSpec
	Reviews      []gitcore.Review
}

// ChecksState is the combined state for the API enum (pending|success|failure).
func (a Assessment) ChecksState() string { return CombinedState(a.Checks) }

// CombinedState maps a CheckSet to the API enum.
func CombinedState(cs *gitcore.CheckSet) string {
	if cs == nil {
		return "success"
	}
	switch cs.State {
	case gitcore.CheckPending:
		return "pending"
	case gitcore.CheckFailure, gitcore.CheckError:
		return "failure"
	}
	for _, c := range cs.Items {
		switch c.State {
		case gitcore.CheckFailure, gitcore.CheckError:
			return "failure"
		case gitcore.CheckPending:
			return "pending"
		}
	}
	return "success"
}

// Assess gathers protection, checks, reviews, ancestry and signatures from gitcore and evaluates.
// Any upstream error is returned: callers must not present the pull request as mergeable then.
func Assess(ctx context.Context, core gitcore.Core, ref gitcore.RepoRef, p gitcore.Pull) (*Assessment, error) {
	a := &Assessment{}
	if p.State != gitcore.PullOpen {
		a.Mergeability = Evaluate(Inputs{Pull: p})
		return a, nil
	}
	rules, err := core.ListProtections(ctx, ref)
	if err != nil {
		return nil, err
	}
	a.Rule = MatchRule(rules, p.Base)
	if p.HeadSHA != "" {
		if a.Checks, err = core.ListChecks(ctx, ref, p.HeadSHA); err != nil {
			return nil, err
		}
	}
	in := Inputs{Pull: p, Rule: a.Rule, Checks: a.Checks}
	if r := a.Rule; r != nil {
		if r.RequiredApprovals > 0 || r.BlockOnRejectedReviews {
			if in.Reviews, err = core.ListReviews(ctx, ref, p.Number); err != nil {
				return nil, err
			}
			a.Reviews = in.Reviews
		}
		if r.BlockOnOutdatedBranch && p.HeadSHA != "" {
			cmp, err := core.Compare(ctx, ref, p.HeadSHA, p.Base)
			if err != nil {
				return nil, err
			}
			in.BehindBase = cmp.AheadBy > 0
		}
		if r.RequireSignedCommits {
			cs, err := core.PullCommits(ctx, ref, p.Number, gitcore.Page{Limit: maxSignedLookup})
			if err != nil {
				return nil, err
			}
			for _, c := range cs.Items {
				if !c.Verified {
					s := c.SHA
					if len(s) > 7 {
						s = s[:7]
					}
					in.Unsigned = append(in.Unsigned, s)
				}
			}
			if cs.NextCursor != "" { // more commits than we looked at: cannot prove they are signed
				in.Unsigned = append(in.Unsigned, "(more than 100 commits)")
			}
		}
	}
	in.Extra = extraBlockers(ctx, ref, p)
	a.Mergeability = Evaluate(in)
	return a, nil
}

// CountApprovals is the number of qualifying approvals under the given rule.
func CountApprovals(reviews []gitcore.Review, r gitcore.ProtectionSpec) int {
	n, _ := countReviews(reviews, r)
	return n
}
