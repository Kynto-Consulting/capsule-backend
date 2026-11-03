package gitprotect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// roleTeam is the Forgejo team of a role in a project (same names as internal/forgejo.ProjectTeams).
func roleTeam(projectSlug, role string) string { return projectSlug + "-" + role }

func roleTeams(projectSlug string, roles []string) []string {
	out := []string{}
	for _, r := range roles {
		out = append(out, roleTeam(projectSlug, r))
	}
	sort.Strings(out)
	return out
}

// RequiredContexts are the status contexts Forgejo must see green: the rule's own checks plus
// the Capsule contexts implied by block_on_security_policy.
func RequiredContexts(r Rule) []string {
	out := append([]string{}, r.RequiredChecks...)
	if r.BlockOnSecurityPolicy {
		for _, c := range []string{CtxSecurity, CtxPolicy} {
			dup := false
			for _, o := range out {
				if o == c {
					dup = true
				}
			}
			if !dup {
				out = append(out, c)
			}
		}
	}
	return out
}

// BuildSpec translates a Capsule rule into the full Forgejo rule (the whole desired state is
// always sent, so applying it twice is a no-op).
//
//	require_pull_request            -> enable_push=false (nobody pushes directly)
//	push_allow_roles                -> enable_push + push whitelist with the <slug>-<role> teams
//	(no PR required)                -> enable_push=true, no whitelist
//	required_approvals ...          -> required_approvals, dismiss_stale_approvals, block_on_rejected_reviews
//	require_code_owner_review       -> block_on_official_review_requests
//	required_checks / policy        -> enable_status_check + status_check_contexts
//	require_up_to_date              -> block_on_outdated_branch
//	require_signed_commits          -> require_signed_commits
//	merge_allow_roles               -> merge whitelist with the role teams
//	enforce_for_admins              -> apply_to_admins
//
// Not projected to Forgejo: require_linear_history (handled by restricting merge styles on the
// repository), delete_branch_on_merge (repository-wide setting), block_force_push and
// block_deletion (always true natively).
func BuildSpec(r Rule, projectSlug string) gitcore.ProtectionSpec {
	s := gitcore.ProtectionSpec{
		RuleName:                     r.Pattern,
		RequiredApprovals:            r.RequiredApprovals,
		BlockOnRejectedReviews:       r.BlockOnRejectedReviews,
		BlockOnOfficialReviewRequest: r.RequireCodeOwnerReview,
		BlockOnOutdatedBranch:        r.RequireUpToDate,
		DismissStaleApprovals:        r.DismissStaleApprovals,
		RequireSignedCommits:         r.RequireSignedCommits,
		ApplyToAdmins:                r.EnforceForAdmins,
	}
	switch {
	case !r.RequirePullRequest:
		s.EnablePush = true
	case len(r.PushAllowRoles) > 0:
		s.EnablePush = true
		s.EnablePushWhitelist = true
		s.PushWhitelistTeams = roleTeams(projectSlug, r.PushAllowRoles)
	}
	if len(r.MergeAllowRoles) > 0 {
		s.EnableMergeWhitelist = true
		s.MergeWhitelistTeams = roleTeams(projectSlug, r.MergeAllowRoles)
	}
	if ctx := RequiredContexts(r); len(ctx) > 0 {
		s.EnableStatusCheck = true
		s.StatusCheckContexts = ctx
	}
	return normSpec(s)
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

// normSpec makes specs comparable: nil == empty, string sets sorted.
func normSpec(s gitcore.ProtectionSpec) gitcore.ProtectionSpec {
	s.PushWhitelistUsers = sortedCopy(s.PushWhitelistUsers)
	s.PushWhitelistTeams = sortedCopy(s.PushWhitelistTeams)
	s.MergeWhitelistUsers = sortedCopy(s.MergeWhitelistUsers)
	s.MergeWhitelistTeams = sortedCopy(s.MergeWhitelistTeams)
	s.StatusCheckContexts = sortedCopy(s.StatusCheckContexts)
	s.ApprovalsWhitelistUsers = sortedCopy(s.ApprovalsWhitelistUsers)
	s.ApprovalsWhitelistTeams = sortedCopy(s.ApprovalsWhitelistTeams)
	return s
}

// specFields flattens a spec to name -> value (strings sorted/joined into []string).
func specFields(s gitcore.ProtectionSpec) map[string]any {
	s = normSpec(s)
	return map[string]any{
		"rule_name": s.RuleName, "enable_push": s.EnablePush, "enable_push_whitelist": s.EnablePushWhitelist,
		"push_whitelist_users": s.PushWhitelistUsers, "push_whitelist_teams": s.PushWhitelistTeams,
		"push_whitelist_deploy_keys": s.PushWhitelistDeployKeys,
		"enable_merge_whitelist":     s.EnableMergeWhitelist, "merge_whitelist_users": s.MergeWhitelistUsers, "merge_whitelist_teams": s.MergeWhitelistTeams,
		"enable_status_check": s.EnableStatusCheck, "status_check_contexts": s.StatusCheckContexts,
		"required_approvals":         s.RequiredApprovals,
		"enable_approvals_whitelist": s.EnableApprovalsWhitelist, "approvals_whitelist_users": s.ApprovalsWhitelistUsers, "approvals_whitelist_teams": s.ApprovalsWhitelistTeams,
		"block_on_rejected_reviews": s.BlockOnRejectedReviews, "block_on_official_review_requests": s.BlockOnOfficialReviewRequest,
		"block_on_outdated_branch": s.BlockOnOutdatedBranch, "dismiss_stale_approvals": s.DismissStaleApprovals,
		"ignore_stale_approvals": s.IgnoreStaleApprovals, "require_signed_commits": s.RequireSignedCommits,
		"protected_file_patterns": s.ProtectedFilePatterns, "unprotected_file_patterns": s.UnprotectedFilePatterns,
		"apply_to_admins": s.ApplyToAdmins,
	}
}

// DiffSpec returns the names of the fields that differ (sorted); empty = identical.
func DiffSpec(want, got gitcore.ProtectionSpec) []string {
	w, g := specFields(want), specFields(got)
	var out []string
	for k, wv := range w {
		a, _ := json.Marshal(wv)
		b, _ := json.Marshal(g[k])
		if string(a) != string(b) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// diffValues is {field: {"forgejo": ..., "desired": ...}} for the audit trail.
func diffValues(want, got gitcore.ProtectionSpec, fields []string) map[string]any {
	w, g := specFields(want), specFields(got)
	out := map[string]any{}
	for _, f := range fields {
		out[f] = map[string]any{"forgejo": g[f], "desired": w[f]}
	}
	return out
}

// SpecHash identifies a desired spec (stored in branch_protection_sync).
func SpecHash(s gitcore.ProtectionSpec) string {
	b, _ := json.Marshal(specFields(s))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
