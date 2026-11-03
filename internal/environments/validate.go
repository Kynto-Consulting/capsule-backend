package environments

import (
	"fmt"
	"regexp"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitprotect"
)

var envNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

// Normalize validates in and applies the defaults of its kind, producing the full policy
// (a PUT replaces everything: an absent field returns to its default). self is the project the
// environment belongs to (the default target).
//
// Production defaults follow the owner's decision: 1 approval from an admin other than the
// requester, no self-approval, admins listed explicitly as approvers.
func Normalize(in Input, self uuid.UUID) (Environment, error) {
	var fe []FieldError
	bad := func(f, m string) { fe = append(fe, FieldError{f, m}) }
	e := Environment{Name: in.Name, Kind: in.Kind, TargetProjectID: self}
	if !envNameRE.MatchString(in.Name) {
		bad("name", "must match ^[a-z][a-z0-9-]{1,30}$")
	}
	switch in.Kind {
	case "staging", "production", "other":
	default:
		bad("kind", "must be staging, production or other")
	}
	prod := in.Kind == "production"
	if in.TargetProjectID != nil {
		e.TargetProjectID = *in.TargetProjectID
	}
	e.BranchPatterns = patterns(in.BranchPatterns, "branch_patterns", bad)
	e.TagPatterns = patterns(in.TagPatterns, "tag_patterns", bad)
	e.AutoDeploy = in.AutoDeploy != nil && *in.AutoDeploy

	e.RequiredApprovals = 0
	if prod {
		e.RequiredApprovals = 1
	}
	if in.RequiredApprovals != nil {
		e.RequiredApprovals = *in.RequiredApprovals
	}
	if e.RequiredApprovals < 0 || e.RequiredApprovals > 5 {
		bad("required_approvals", "must be between 0 and 5")
	}
	if prod && e.RequiredApprovals < 1 {
		bad("required_approvals", "production requires at least 1 approval")
	}
	e.AllowSelfApproval = in.AllowSelfApproval != nil && *in.AllowSelfApproval
	e.WaitMinutes = 0
	if in.WaitMinutes != nil {
		e.WaitMinutes = *in.WaitMinutes
	}
	if e.WaitMinutes < 0 || e.WaitMinutes > 43200 {
		bad("wait_minutes", "must be between 0 and 43200")
	}

	e.Reviewers = in.Reviewers
	if e.Reviewers == nil {
		e.Reviewers = []Reviewer{}
		if prod {
			e.Reviewers = []Reviewer{{Type: "role", Role: "admin"}}
		}
	}
	if len(e.Reviewers) > 20 {
		bad("reviewers", "at most 20 entries")
	}
	seen := map[string]bool{}
	users := map[uuid.UUID]bool{}
	onlyUsers := true
	for i, r := range e.Reviewers {
		f := fmt.Sprintf("reviewers[%d]", i)
		key := ""
		switch r.Type {
		case "user":
			if r.UserID == nil || *r.UserID == uuid.Nil {
				bad(f+".user_id", "required for type user")
			} else {
				key = "u:" + r.UserID.String()
				users[*r.UserID] = true
			}
		case "role":
			onlyUsers = false
			if r.Role != "admin" && r.Role != "deployer" {
				bad(f+".role", "must be admin or deployer")
			} else if prod && r.Role != "admin" {
				bad(f+".role", "production approvers must be admins")
			}
			key = "r:" + r.Role
		default:
			bad(f+".type", "must be user or role")
		}
		if key != "" {
			if seen[key] {
				bad(f, "duplicate approver")
			}
			seen[key] = true
		}
	}
	if e.RequiredApprovals > 0 && len(e.Reviewers) == 0 {
		bad("reviewers", "required when approvals are required")
	}
	// one listed user may be the requester, so N approvals need N+1 listed people
	if e.RequiredApprovals > 0 && onlyUsers && len(e.Reviewers) > 0 && !e.AllowSelfApproval && len(users) <= e.RequiredApprovals {
		bad("required_approvals", "needs more listed approvers than approvals (the requester cannot approve)")
	}

	e.Windows = in.Windows
	if e.Windows == nil {
		e.Windows = []Window{}
	}
	if len(e.Windows) > 14 {
		bad("windows", "at most 14 windows")
	}
	for i, w := range e.Windows {
		if m := ValidateWindow(w); m != "" {
			bad(fmt.Sprintf("windows[%d]", i), m)
		}
		if e.Windows[i].Days == nil {
			e.Windows[i].Days = []string{}
		}
	}

	e.RequireChecksOnSHA = prod || in.Kind == "staging"
	if in.RequireChecksOnSHA != nil {
		e.RequireChecksOnSHA = *in.RequireChecksOnSHA
	}
	e.RequireSecurityPolicy = prod
	if in.RequireSecurityPolicy != nil {
		e.RequireSecurityPolicy = *in.RequireSecurityPolicy
	}
	e.RollbackRequiresApproval = in.RollbackRequiresApproval != nil && *in.RollbackRequiresApproval
	if in.RequireSourceEnvironment != nil && *in.RequireSourceEnvironment != "" {
		s := *in.RequireSourceEnvironment
		if !envNameRE.MatchString(s) {
			bad("require_source_environment", "invalid environment name")
		} else if s == in.Name {
			bad("require_source_environment", "cannot be the environment itself")
		}
		e.RequireSourceEnvironment = &s
	}
	if len(fe) > 0 {
		return Environment{}, &ValidationError{Fields: fe}
	}
	return e, nil
}

func patterns(in []string, field string, bad func(string, string)) []string {
	if len(in) > 20 {
		bad(field, "at most 20 patterns")
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for i, p := range in {
		if _, err := gitprotect.CompileGlob(p); err != nil {
			bad(fmt.Sprintf("%s[%d]", field, i), err.Error())
			continue
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// MatchAny reports whether name matches any glob (invalid patterns never match).
func MatchAny(pats []string, name string) bool {
	for _, p := range pats {
		if g, err := gitprotect.CompileGlob(p); err == nil && g.Match(name) {
			return true
		}
	}
	return false
}
