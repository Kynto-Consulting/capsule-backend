package gitprotect

import (
	"context"

	"github.com/kynto/capsule/backend/internal/gitcore"
)

// ProjectTags projects the protected-tag patterns (GITPROTECT_TAG_PATTERNS, default "v*") onto
// Forgejo's tag protection, so a `git push` of a tag is covered too (GuardTag only covers the
// Capsule API). Only the project's admin team may create or delete a matching tag: Forgejo's
// whitelist is exclusive (an empty one means nobody, and the service account is not exempt, both
// verified on v15.0.11), so Capsule's own tag calls act as the requesting user via Sudo.
//
// It is idempotent and never lowers protection: a rule is edited in place (no delete + create
// window), rules Capsule does not manage are left alone. Forgejo silently drops a whitelisted team
// that has no access to the repository, so the team must be attached first (gitsync does it).
// It does nothing when the core cannot manage tag protection.
func (s *Service) ProjectTags(ctx context.Context, t Target) error {
	tp, ok := s.forge.(gitcore.TagProtections)
	if !ok || len(s.cfg.TagPatterns) == 0 || !s.forge.Enabled() {
		return nil
	}
	ref := s.ref(t)
	live, err := tp.ListTagProtections(ctx, ref)
	if err != nil {
		return err
	}
	byPattern := map[string]gitcore.TagProtection{}
	for _, p := range live {
		byPattern[p.Pattern] = p
	}
	team := roleTeam(t.ProjectSlug, RoleAdmin)
	var first error
	for _, pat := range s.cfg.TagPatterns {
		want := gitcore.TagProtectionSpec{Pattern: pat, WhitelistTeams: []string{team}}
		cur, present := byPattern[pat]
		var err error
		switch {
		case !present:
			_, err = tp.CreateTagProtection(ctx, ref, want)
		case len(cur.WhitelistUsers) != 0 || !sameSet(cur.WhitelistTeams, want.WhitelistTeams):
			_, err = tp.EditTagProtection(ctx, ref, cur.ID, want)
		}
		if err != nil {
			s.log.Warn("gitprotect: tag protection not applied", "project", t.ProjectID, "pattern", pat, "err", describe(err))
			if first == nil {
				first = err
			}
		}
	}
	return first
}
