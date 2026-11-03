package gittokens

import (
	"context"
	"time"
)

// Run is the background loop: it retries pending SSH key synchronizations every two minutes,
// sends the 7-day expiry warnings (when a Notifier is set) and purges old ephemeral tokens once
// an hour. It returns when ctx is done.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	lastPurge := s.now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.Tick(ctx)
		if s.now().Sub(lastPurge) >= time.Hour {
			lastPurge = s.now()
			if n, err := s.d.Store.PurgeEphemeral(ctx, s.now().Add(-7*24*time.Hour)); err != nil {
				s.log().Warn("git tokens: purge failed", "error", err.Error())
			} else if n > 0 {
				s.log().Info("git tokens: purged ephemeral tokens", "rows", n)
			}
		}
	}
}

// Tick runs one maintenance pass (exported for tests and for an external scheduler).
func (s *Service) Tick(ctx context.Context) {
	if _, err := s.SyncPending(ctx, 50); err != nil {
		s.log().Warn("git keys: reconcile failed", "error", err.Error())
	}
	s.WarnExpiring(ctx)
}

// WarnExpiring notifies the owners of personal and service tokens that expire within WarnBefore.
func (s *Service) WarnExpiring(ctx context.Context) int {
	if s.d.Notifier == nil {
		return 0
	}
	now := s.now()
	list, err := s.d.Store.ListExpiring(ctx, now, now.Add(s.cfg.WarnBefore), 100)
	if err != nil {
		s.log().Warn("git tokens: listing expiring tokens failed", "error", err.Error())
		return 0
	}
	n := 0
	for _, t := range list {
		if t.Kind == KindEphemeral || t.ExpiryWarnedAt != nil {
			continue
		}
		if err := s.d.Notifier.TokenExpiring(ctx, t); err != nil {
			s.log().Warn("git tokens: expiry notification failed", "token", t.ID.String(), "error", err.Error())
			continue
		}
		if err := s.d.Store.MarkExpiryWarned(ctx, t.ID); err == nil {
			n++
		}
	}
	return n
}
