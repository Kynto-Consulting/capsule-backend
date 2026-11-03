package gitprotect

import (
	"context"
	"fmt"

	"github.com/kynto/capsule/backend/internal/gitsource"
)

// This file holds the A4 policy that the repository-settings and tag routes (owned by B1:
// repoUpdate, tagCreate, tagDelete) must apply. B1 calls these two hooks; A4 does not mount
// those routes itself, so there is a single handler per operation.

// MergeStyles are the strategies a repository can offer (SPEC 5.4).
var MergeStyles = []string{"merge", "squash", "rebase", "fast-forward"}

// CheckMergeStyles is the repoUpdate hook for allowed_merge_styles. It refuses (PolicyError
// POLICY_BLOCKED, 422) a set that includes merge or squash while a rule requires linear history,
// naming the rule, because Forgejo has no native "linear history" and Capsule enforces it by
// restricting the styles. nil styles = untouched (always ok).
func (s *Service) CheckMergeStyles(ctx context.Context, t Target, styles []string) error {
	if styles == nil {
		return nil
	}
	rules, err := s.store.ListRules(ctx, t.ProjectID)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if !r.RequireLinearHistory {
			continue
		}
		for _, st := range styles {
			if !inSet(linearStyles, st) {
				return &PolicyError{Code: "POLICY_BLOCKED", Message: fmt.Sprintf("la regla «%s» exige historial lineal: solo se admiten rebase y fast-forward (quite «%s» o desactive el historial lineal en la regla)", r.Pattern, st)}
			}
		}
	}
	return nil
}

// TagProtected reports whether name matches a protected-tag pattern (default "v*"), and which.
func (s *Service) TagProtected(name string) (pattern string, protected bool) {
	for _, p := range s.cfg.TagPatterns {
		if g, err := CompileGlob(p); err == nil && g.Match(name) {
			return p, true
		}
	}
	return "", false
}

// GuardTag is the tagCreate/tagDelete hook: protected tags (GITPROTECT_TAG_PATTERNS, default
// "v*") may only be created or deleted by a project admin (isGitAdmin = holds git.admin).
// It returns a ForbiddenError PROTECTED_TAG (403) otherwise. Capsule decides this itself because
// gitcore does not expose Forgejo's tag-protection API (limitation reported by A4): a `git push`
// of a tag is not covered by this guard.
func (s *Service) GuardTag(name string, isGitAdmin bool, op string) error {
	if !gitsource.ValidBranch(name) {
		return &ValidationError{Fields: []FieldError{{Field: "tag", Message: "nombre de etiqueta inválido"}}}
	}
	if pat, prot := s.TagProtected(name); prot && !isGitAdmin {
		return &ForbiddenError{Code: "PROTECTED_TAG", Message: fmt.Sprintf("la etiqueta «%s» está protegida por el patrón «%s»: solo un administrador del proyecto puede %s", name, pat, op)}
	}
	return nil
}
