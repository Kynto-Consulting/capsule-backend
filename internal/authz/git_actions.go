package authz

// Git Capsule actions (docs/git-capsule/SPEC.md). Baseline created by the integrator so every
// package builds against the same names; package A2 owns this file from here on and extends it.
//
// They are registered into the role matrix from init() rather than listed in AllActions, so the
// existing project-action decision-table tests keep their meaning; GitActions lists these.
const (
	GitRead        Action = "git.read"        // browse code, branches, commits, PRs, runs
	GitWrite       Action = "git.write"       // create/delete branches, open PRs, comment
	GitReview      Action = "git.review"      // submit reviews
	GitMerge       Action = "git.merge"       // merge PRs (subject to branch protection)
	GitAdmin       Action = "git.admin"       // protections, repo settings, mirrors, dismiss reviews
	SecurityRead   Action = "security.read"   // see alerts
	SecurityTriage Action = "security.triage" // dismiss low/medium alerts with justification
	SecurityAdmin  Action = "security.admin"  // dismiss critical/high, policies
	EnvRead        Action = "env.read"        // see environments and promotions
	EnvRequest     Action = "env.request"     // request a promotion
	EnvAdmin       Action = "env.admin"       // configure environments
	EnvApprove     Action = "env.approve"     // approve a promotion: granted by the environment's approver list, not by role
	WebhooksManage Action = "webhooks.manage" // outbound webhooks
)

// GitActions lists the Git Capsule actions (tests and docs).
var GitActions = []Action{
	GitRead, GitWrite, GitReview, GitMerge, GitAdmin,
	SecurityRead, SecurityTriage, SecurityAdmin,
	EnvRead, EnvRequest, EnvAdmin, EnvApprove, WebhooksManage,
}

func init() {
	grant := func(r Role, as ...Action) {
		for _, a := range as {
			matrix[r][a] = true
		}
	}
	grant(RoleViewer, GitRead, SecurityRead, EnvRead)
	grant(RoleDeployer, GitRead, GitWrite, GitReview, GitMerge, SecurityRead, SecurityTriage, EnvRead, EnvRequest)
	grant(RoleAdmin, GitRead, GitWrite, GitReview, GitMerge, GitAdmin,
		SecurityRead, SecurityTriage, SecurityAdmin, EnvRead, EnvRequest, EnvAdmin, WebhooksManage)
	// EnvApprove is intentionally absent from every role: the environment's approver list decides.
}

// IsGitAction reports whether a is one of the Git Capsule actions.
func IsGitAction(a Action) bool {
	for _, g := range GitActions {
		if g == a {
			return true
		}
	}
	return false
}

// GitActionsFor lists the Git Capsule actions the role grants, in GitActions order.
func GitActionsFor(role Role) []Action {
	var out []Action
	for _, a := range GitActions {
		if RoleAllows(role, a) {
			out = append(out, a)
		}
	}
	return out
}

// CanGit is the pure form of Service.Can for the Git Capsule actions: org role x access mode x
// explicit project role -> allowed. A hidden or non-member user is never allowed.
func CanGit(orgRole, mode, explicit string, a Action) bool {
	return RoleAllows(Resolve(orgRole, mode, explicit).Role, a)
}
