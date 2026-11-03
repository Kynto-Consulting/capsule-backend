package gitreview

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/gitapi"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

// Owner resolution statuses.
const (
	OwnerOK           = "ok"
	OwnerUnknownUser  = "unknown_user"     // no Capsule member has that Forgejo login
	OwnerNoReview     = "no_review_access" // member, but the role cannot review (viewer)
	OwnerUnknownTeam  = "unknown_team"     // not one of the project role teams
	teamRoleSeparator = "-"
)

// OwnerRef is one CODEOWNERS owner resolved to Capsule users.
type OwnerRef struct {
	Raw    string
	Status string
	Users  []Member // members that can review (empty unless Status == ok)
}

// ResolveOwners resolves raw owners against the roster. @user matches the Forgejo login (case
// insensitive); @org/team only resolves for the project role teams <slug>-admin|deployer|viewer.
func ResolveOwners(raw []string, p Project, roster []Member) map[string]OwnerRef {
	byLogin := map[string]Member{}
	for _, m := range roster {
		byLogin[strings.ToLower(m.Login)] = m
	}
	out := make(map[string]OwnerRef, len(raw))
	for _, o := range raw {
		ref := OwnerRef{Raw: o}
		name := strings.TrimPrefix(o, "@")
		if org, team, isTeam := strings.Cut(name, "/"); isTeam {
			ref.Status = OwnerUnknownTeam
			if strings.EqualFold(org, p.Ref.Owner) {
				for _, role := range []authz.Role{authz.RoleAdmin, authz.RoleDeployer, authz.RoleViewer} {
					if !strings.EqualFold(team, p.Ref.Repo+teamRoleSeparator+string(role)) {
						continue
					}
					ref.Status = OwnerNoReview
					for _, m := range roster {
						if m.Role == role && authz.RoleAllows(m.Role, authz.GitReview) {
							ref.Users = append(ref.Users, m)
						}
					}
					if len(ref.Users) > 0 {
						ref.Status = OwnerOK
					}
				}
			}
		} else if m, ok := byLogin[strings.ToLower(name)]; !ok {
			ref.Status = OwnerUnknownUser
		} else if !authz.RoleAllows(m.Role, authz.GitReview) {
			ref.Status = OwnerNoReview
		} else {
			ref.Status, ref.Users = OwnerOK, []Member{m}
		}
		out[o] = ref
	}
	return out
}

// OwnerGroup is a set of owners that covers some changed files; one approval from any of them
// satisfies the group.
type OwnerGroup struct {
	Owners     []string `json:"owners"` // logins
	Files      int      `json:"files"`
	Satisfied  bool     `json:"satisfied"`
	ApprovedBy string   `json:"approved_by,omitempty"`
}

// Status is the review situation of a pull request.
type Status struct {
	RequiredApprovals  int          `json:"required_approvals"`
	Approvals          int          `json:"approvals"`
	Pending            []string     `json:"pending"`              // requested reviewers who have not decided
	ChangesRequestedBy []string     `json:"changes_requested_by"` // latest decision is "changes requested"
	StaleApprovals     []string     `json:"stale_approvals"`
	CodeOwnerRequired  bool         `json:"code_owner_required"`
	CodeOwnerGroups    []OwnerGroup `json:"code_owner_groups"`
	CodeOwnerPending   []string     `json:"code_owner_pending"`
	Warnings           []string     `json:"warnings"`
}

// StatusInput feeds ComputeStatus (pure, table-tested).
type StatusInput struct {
	Pull     gitcore.Pull
	Reviews  []gitcore.Review
	Rule     *gitcore.ProtectionSpec
	Owners   *File    // nil = no CODEOWNERS
	Files    []string // changed paths
	Resolved map[string]OwnerRef
}

// ComputeStatus derives required/pending reviews and code owner coverage.
func ComputeStatus(in StatusInput) Status {
	st := Status{Pending: []string{}, ChangesRequestedBy: []string{}, StaleApprovals: []string{}, CodeOwnerGroups: []OwnerGroup{},
		CodeOwnerPending: []string{}, Warnings: []string{}}
	if in.Rule != nil {
		st.RequiredApprovals = in.Rule.RequiredApprovals
		st.Approvals = gitapi.CountApprovals(in.Reviews, *in.Rule)
		st.CodeOwnerRequired = in.Rule.BlockOnOfficialReviewRequest
	}
	staleCounts := in.Rule == nil || !(in.Rule.DismissStaleApprovals || in.Rule.IgnoreStaleApprovals)

	revs := append([]gitcore.Review(nil), in.Reviews...)
	sort.SliceStable(revs, func(i, j int) bool { return revs[i].ID < revs[j].ID })
	latest := map[string]gitcore.Review{}
	for _, r := range revs {
		switch r.State {
		case "approved", "changes_requested", "dismissed":
			latest[strings.ToLower(r.Author.Login)] = r
		}
	}
	decided := map[string]bool{}
	approved := map[string]bool{} // logins with an approval that counts for code owners
	for login, r := range latest {
		decided[login] = true
		switch r.State {
		case "changes_requested":
			st.ChangesRequestedBy = append(st.ChangesRequestedBy, r.Author.Login)
		case "approved":
			if r.Stale {
				st.StaleApprovals = append(st.StaleApprovals, r.Author.Login)
			}
			if !r.Stale || staleCounts {
				approved[login] = true
			}
		}
	}
	for _, u := range in.Pull.Reviewers {
		if !decided[strings.ToLower(u.Login)] {
			st.Pending = append(st.Pending, u.Login)
		}
	}
	sort.Strings(st.ChangesRequestedBy)
	sort.Strings(st.StaleApprovals)
	sort.Strings(st.Pending)

	if in.Owners == nil || !st.CodeOwnerRequired {
		return st
	}
	author := strings.ToLower(in.Pull.Author.Login)
	type agg struct {
		owners []string
		files  int
		ok     bool
		by     string
	}
	groups := map[string]*agg{}
	warned := map[string]bool{}
	for _, f := range in.Files {
		raw := in.Owners.OwnersOf(f)
		if len(raw) == 0 {
			continue
		}
		set := map[string]bool{}
		for _, o := range raw {
			ref, found := in.Resolved[o]
			if !found || ref.Status != OwnerOK {
				if !warned[o] {
					warned[o] = true
					status := OwnerUnknownUser
					if found {
						status = ref.Status
					}
					st.Warnings = append(st.Warnings, fmt.Sprintf("propietario %s no se puede resolver (%s); no se exige su revision", o, status))
				}
				continue
			}
			for _, m := range ref.Users {
				set[strings.ToLower(m.Login)] = true
			}
		}
		if len(set) == 0 {
			continue // every owner of this file is unresolvable: nobody can be asked
		}
		delete(set, author) // nobody approves their own pull request
		logins := sortedKeys(set)
		key := strings.Join(logins, ",")
		g := groups[key]
		if g == nil {
			g = &agg{owners: logins}
			for _, l := range logins {
				if approved[l] {
					g.ok, g.by = true, l
					break
				}
			}
			groups[key] = g
		}
		g.files++
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pend := map[string]bool{}
	for _, k := range keys {
		g := groups[k]
		og := OwnerGroup{Owners: g.owners, Files: g.files, Satisfied: g.ok, ApprovedBy: g.by}
		if og.Owners == nil {
			og.Owners = []string{}
		}
		st.CodeOwnerGroups = append(st.CodeOwnerGroups, og)
		if !g.ok {
			if len(g.owners) == 0 {
				st.Warnings = append(st.Warnings, "hay archivos cuyo unico propietario es el autor del PR: otra persona debe ser propietaria o se debe ajustar CODEOWNERS")
			}
			for _, l := range g.owners {
				pend[l] = true
			}
		}
	}
	st.CodeOwnerPending = sortedKeys(pend)
	return st
}

// Unsatisfied reports whether code owner coverage is missing.
func (s Status) Unsatisfied() bool {
	for _, g := range s.CodeOwnerGroups {
		if !g.Satisfied {
			return true
		}
	}
	return false
}
