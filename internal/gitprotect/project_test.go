package gitprotect

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

func bp(v bool) *bool { return &v }
func ip(v int) *int   { return &v }

func TestNormalizeSafeDefaults(t *testing.T) {
	r, warns, err := Normalize(Input{Pattern: " main "})
	if err != nil {
		t.Fatal(err)
	}
	want := Rule{Pattern: "main", RequirePullRequest: true, DismissStaleApprovals: true, BlockOnRejectedReviews: true,
		BlockForcePush: true, BlockDeletion: true, EnforceForAdmins: true,
		RequiredChecks: []string{}, PushAllowRoles: []string{}, MergeAllowRoles: []string{}}
	if !reflect.DeepEqual(r, want) {
		t.Fatalf("defaults:\n got %+v\nwant %+v", r, want)
	}
	if len(warns) != 0 {
		t.Fatalf("defaults must not warn: %v", warns)
	}
}

func TestNormalizeExplicitFalseIsKept(t *testing.T) {
	r, _, err := Normalize(Input{Pattern: "main", RequirePullRequest: bp(false), DismissStaleApprovals: bp(false), BlockOnRejectedReviews: bp(false), EnforceForAdmins: bp(false)})
	if err != nil {
		t.Fatal(err)
	}
	if r.RequirePullRequest || r.DismissStaleApprovals || r.BlockOnRejectedReviews || r.EnforceForAdmins {
		t.Fatalf("explicit false must override the default: %+v", r)
	}
}

func fieldsOf(t *testing.T, err error) []string {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	var out []string
	for _, f := range ve.Fields {
		out = append(out, f.Field)
	}
	return out
}

func TestNormalizeValidation(t *testing.T) {
	cases := []struct {
		name  string
		in    Input
		field string
	}{
		{"empty pattern", Input{}, "pattern"},
		{"space", Input{Pattern: "a b"}, "pattern"},
		{"leading slash", Input{Pattern: "/main"}, "pattern"},
		{"trailing slash", Input{Pattern: "main/"}, "pattern"},
		{"double slash", Input{Pattern: "a//b"}, "pattern"},
		{"dotdot", Input{Pattern: "a/../b"}, "pattern"},
		{"control", Input{Pattern: "a\x00b"}, "pattern"},
		{"bad glob", Input{Pattern: "a["}, "pattern"},
		{"approvals low", Input{Pattern: "m", RequiredApprovals: ip(-1)}, "required_approvals"},
		{"approvals high", Input{Pattern: "m", RequiredApprovals: ip(11)}, "required_approvals"},
		{"empty check", Input{Pattern: "m", RequiredChecks: []string{" "}}, "required_checks"},
		{"long check", Input{Pattern: "m", RequiredChecks: []string{strings.Repeat("x", 201)}}, "required_checks"},
		{"too many checks", Input{Pattern: "m", RequiredChecks: manyChecks(31)}, "required_checks"},
		{"bad push role", Input{Pattern: "m", PushAllowRoles: []string{"viewer"}}, "push_allow_roles"},
		{"bad merge role", Input{Pattern: "m", MergeAllowRoles: []string{"owner"}}, "merge_allow_roles"},
		{"force push off", Input{Pattern: "m", BlockForcePush: bp(false)}, "block_force_push"},
		{"deletion off", Input{Pattern: "m", BlockDeletion: bp(false)}, "block_deletion"},
		{"push roles without PR", Input{Pattern: "m", RequirePullRequest: bp(false), PushAllowRoles: []string{"admin"}}, "push_allow_roles"},
	}
	for _, c := range cases {
		_, _, err := Normalize(c.in)
		fs := fieldsOf(t, err)
		found := false
		for _, f := range fs {
			found = found || f == c.field
		}
		if !found {
			t.Errorf("%s: fields %v, want %s", c.name, fs, c.field)
		}
	}
	if _, _, err := Normalize(Input{Pattern: strings.Repeat("a", 256)}); err == nil {
		t.Error("256-char pattern must fail")
	}
}

func manyChecks(n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, "ci/"+strings.Repeat("a", i+1))
	}
	return out
}

func TestNormalizeCleansLists(t *testing.T) {
	r, _, err := Normalize(Input{Pattern: "m", RequiredChecks: []string{" ci/a ", "ci/a", "ci/b"}, PushAllowRoles: []string{"deployer", "admin", "admin"}, MergeAllowRoles: []string{"deployer"}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.RequiredChecks, []string{"ci/a", "ci/b"}) || !reflect.DeepEqual(r.PushAllowRoles, []string{"admin", "deployer"}) {
		t.Fatalf("lists not cleaned: %+v", r)
	}
}

func TestNormalizeWarnings(t *testing.T) {
	_, w, err := Normalize(Input{Pattern: "m", RequirePullRequest: bp(false), RequiredApprovals: ip(1), EnforceForAdmins: bp(false)})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(w, "|")
	if !strings.Contains(joined, "PR_RULES_BYPASSABLE") || !strings.Contains(joined, "ADMINS_EXEMPT") {
		t.Fatalf("warnings: %v", w)
	}
	if w := unknownContextWarnings(Rule{RequiredChecks: []string{"capsule/securty", "capsule/security", "capsule/env:prod", "ci/build"}}); len(w) != 1 || !strings.Contains(w[0], "capsule/securty") {
		t.Fatalf("unknown context warnings: %v", w)
	}
}

// Every field of a Capsule rule must end up in the Forgejo DTO (the matrix of A4's acceptance).
func TestBuildSpecMapsEveryField(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		want gitcore.ProtectionSpec
	}{
		{"PR required, nobody pushes", Rule{Pattern: "main", RequirePullRequest: true, EnforceForAdmins: true},
			gitcore.ProtectionSpec{RuleName: "main", ApplyToAdmins: true}},
		{"no PR: everybody with write pushes", Rule{Pattern: "dev"},
			gitcore.ProtectionSpec{RuleName: "dev", EnablePush: true}},
		{"push whitelist by role teams", Rule{Pattern: "main", RequirePullRequest: true, PushAllowRoles: []string{"admin", "deployer"}},
			gitcore.ProtectionSpec{RuleName: "main", EnablePush: true, EnablePushWhitelist: true, PushWhitelistTeams: []string{"web-admin", "web-deployer"}}},
		{"merge whitelist", Rule{Pattern: "main", RequirePullRequest: true, MergeAllowRoles: []string{"admin"}},
			gitcore.ProtectionSpec{RuleName: "main", EnableMergeWhitelist: true, MergeWhitelistTeams: []string{"web-admin"}}},
		{"approvals and reviews", Rule{Pattern: "main", RequirePullRequest: true, RequiredApprovals: 3, DismissStaleApprovals: true, BlockOnRejectedReviews: true, RequireCodeOwnerReview: true},
			gitcore.ProtectionSpec{RuleName: "main", RequiredApprovals: 3, DismissStaleApprovals: true, BlockOnRejectedReviews: true, BlockOnOfficialReviewRequest: true}},
		{"checks", Rule{Pattern: "main", RequirePullRequest: true, RequiredChecks: []string{"ci/build", "capsule/preview"}},
			gitcore.ProtectionSpec{RuleName: "main", EnableStatusCheck: true, StatusCheckContexts: []string{"capsule/preview", "ci/build"}}},
		{"security policy adds capsule contexts", Rule{Pattern: "main", RequirePullRequest: true, RequiredChecks: []string{"capsule/policy"}, BlockOnSecurityPolicy: true},
			gitcore.ProtectionSpec{RuleName: "main", EnableStatusCheck: true, StatusCheckContexts: []string{"capsule/policy", "capsule/security"}}},
		{"up to date and signed", Rule{Pattern: "main", RequirePullRequest: true, RequireUpToDate: true, RequireSignedCommits: true},
			gitcore.ProtectionSpec{RuleName: "main", BlockOnOutdatedBranch: true, RequireSignedCommits: true}},
		{"linear history, delete on merge, force/deletion are not projected", Rule{Pattern: "main", RequirePullRequest: true, RequireLinearHistory: true, DeleteBranchOnMerge: true, BlockForcePush: true, BlockDeletion: true},
			gitcore.ProtectionSpec{RuleName: "main"}},
		{"admins exempt", Rule{Pattern: "main", RequirePullRequest: true, EnforceForAdmins: false},
			gitcore.ProtectionSpec{RuleName: "main"}},
		{"glob rule name", Rule{Pattern: "release/**", RequirePullRequest: true, EnforceForAdmins: true},
			gitcore.ProtectionSpec{RuleName: "release/**", ApplyToAdmins: true}},
	}
	for _, c := range cases {
		got := BuildSpec(c.rule, "web")
		if d := DiffSpec(normSpec(c.want), got); len(d) > 0 {
			t.Errorf("%s: differing fields %v\n got %+v\nwant %+v", c.name, d, got, normSpec(c.want))
		}
	}
}

func TestDiffSpecNormalizes(t *testing.T) {
	a := gitcore.ProtectionSpec{RuleName: "m", StatusCheckContexts: []string{"b", "a"}}
	b := gitcore.ProtectionSpec{RuleName: "m", StatusCheckContexts: []string{"a", "b"}, PushWhitelistUsers: []string{}}
	if d := DiffSpec(a, b); len(d) != 0 {
		t.Fatalf("order and nil/empty must not count as drift: %v", d)
	}
	b.RequiredApprovals = 1
	b.PushWhitelistUsers = []string{"eve"}
	b.ApplyToAdmins = true
	if d := DiffSpec(a, b); !reflect.DeepEqual(d, []string{"apply_to_admins", "push_whitelist_users", "required_approvals"}) {
		t.Fatalf("diff = %v", d)
	}
	if SpecHash(a) != SpecHash(gitcore.ProtectionSpec{RuleName: "m", StatusCheckContexts: []string{"a", "b"}}) {
		t.Fatal("hash must be order independent")
	}
	if SpecHash(a) == SpecHash(b) {
		t.Fatal("different specs must hash differently")
	}
}

func TestDescribeMentionsWhatIsEnforced(t *testing.T) {
	r, _, _ := Normalize(Input{Pattern: "main", RequiredApprovals: ip(2), RequiredChecks: []string{"ci/build"}, RequireLinearHistory: bp(true), PushAllowRoles: []string{"admin"}, EnforceForAdmins: bp(false)})
	joined := strings.Join(Describe(r), "\n")
	for _, s := range []string{"salvo para: admin", "2 aprobación", "ci/build", "Historial lineal", "exentos"} {
		if !strings.Contains(joined, s) {
			t.Errorf("Describe lacks %q:\n%s", s, joined)
		}
	}
}
