package gitprotect

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxRulesPerProject = 50
	maxChecks          = 30
	maxCheckLen        = 200
)

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// Normalize applies the safe defaults and validates the input. It returns the rule (without
// id/project/timestamps) and any warnings (legal but weaker than they look).
//
// Safe defaults for omitted fields: pull request required, 0 approvals (a default of 1 would
// lock out single-maintainer projects because Forgejo does not let authors approve their own
// PR), stale approvals dismissed, rejected reviews block, force push and deletion blocked,
// rules also bind administrators. The same defaults apply to PUT (replace).
func Normalize(in Input) (Rule, []string, error) {
	var fe []FieldError
	bad := func(f, m string) { fe = append(fe, FieldError{Field: f, Message: m}) }

	r := Rule{
		Pattern:                strings.TrimSpace(in.Pattern),
		RequirePullRequest:     boolOr(in.RequirePullRequest, true),
		DismissStaleApprovals:  boolOr(in.DismissStaleApprovals, true),
		BlockOnRejectedReviews: boolOr(in.BlockOnRejectedReviews, true),
		RequireCodeOwnerReview: boolOr(in.RequireCodeOwnerReview, false),
		RequireUpToDate:        boolOr(in.RequireUpToDate, false),
		RequireSignedCommits:   boolOr(in.RequireSignedCommits, false),
		RequireLinearHistory:   boolOr(in.RequireLinearHistory, false),
		BlockForcePush:         boolOr(in.BlockForcePush, true),
		BlockDeletion:          boolOr(in.BlockDeletion, true),
		EnforceForAdmins:       boolOr(in.EnforceForAdmins, true),
		BlockOnSecurityPolicy:  boolOr(in.BlockOnSecurityPolicy, false),
		DeleteBranchOnMerge:    boolOr(in.DeleteBranchOnMerge, false),
	}
	if in.RequiredApprovals != nil {
		r.RequiredApprovals = *in.RequiredApprovals
	}

	if msg := validPattern(r.Pattern); msg != "" {
		bad("pattern", msg)
	}
	if r.RequiredApprovals < 0 || r.RequiredApprovals > 10 {
		bad("required_approvals", "debe estar entre 0 y 10")
	}
	checks, msg := cleanChecks(in.RequiredChecks)
	if msg != "" {
		bad("required_checks", msg)
	}
	r.RequiredChecks = checks
	var m string
	if r.PushAllowRoles, m = cleanRoles(in.PushAllowRoles); m != "" {
		bad("push_allow_roles", m)
	}
	if r.MergeAllowRoles, m = cleanRoles(in.MergeAllowRoles); m != "" {
		bad("merge_allow_roles", m)
	}
	if !r.BlockForcePush {
		bad("block_force_push", "no se puede desactivar: Forgejo bloquea el force-push en toda rama protegida y Capsule no puede proyectar otra cosa")
	}
	if !r.BlockDeletion {
		bad("block_deletion", "no se puede desactivar: Forgejo no permite borrar una rama protegida; quite la regla antes de borrar la rama")
	}
	if !r.RequirePullRequest && len(r.PushAllowRoles) > 0 {
		bad("push_allow_roles", "solo aplica con require_pull_request=true (son los roles que pueden saltarse el PR); sin PR obligatorio pueden empujar todos los roles con escritura")
	}
	if len(fe) > 0 {
		return Rule{}, nil, &ValidationError{Fields: fe}
	}

	var warn []string
	if !r.RequirePullRequest && (r.RequiredApprovals > 0 || len(r.RequiredChecks) > 0 || r.RequireCodeOwnerReview || r.BlockOnSecurityPolicy) {
		warn = append(warn, "PR_RULES_BYPASSABLE: las aprobaciones y checks solo se exigen al fusionar un PR; sin require_pull_request se pueden eludir con push directo")
	}
	if !r.EnforceForAdmins {
		warn = append(warn, "ADMINS_EXEMPT: los administradores del repositorio en Forgejo no quedan sujetos a esta regla")
	}
	return r, warn, nil
}

func validPattern(p string) string {
	switch {
	case p == "":
		return "es obligatorio"
	case len(p) > maxPatternLen:
		return "máximo 255 caracteres"
	case !utf8.ValidString(p):
		return "debe ser UTF-8 válido"
	case strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/"):
		return "no puede empezar ni terminar en '/'"
	case strings.Contains(p, "//"):
		return "no puede contener '//'"
	case strings.Contains(p, ".."):
		return "no puede contener '..'"
	}
	for _, c := range p {
		if unicode.IsSpace(c) || unicode.IsControl(c) {
			return "no puede contener espacios ni caracteres de control"
		}
	}
	if _, err := CompileGlob(p); err != nil {
		return "patrón glob inválido: " + err.Error()
	}
	return ""
}

func cleanChecks(in []string) ([]string, string) {
	out := []string{}
	seen := map[string]bool{}
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			return nil, "no admite entradas vacías"
		}
		if len(c) > maxCheckLen {
			return nil, "cada contexto admite como máximo 200 caracteres"
		}
		for _, r := range c {
			if unicode.IsControl(r) {
				return nil, "los contextos no pueden contener caracteres de control"
			}
		}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	if len(out) > maxChecks {
		return nil, "máximo 30 contextos"
	}
	return out, ""
}

func cleanRoles(in []string) ([]string, string) {
	out := []string{}
	seen := map[string]bool{}
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r != RoleAdmin && r != RoleDeployer {
			return nil, "valores admitidos: admin, deployer"
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out, ""
}
