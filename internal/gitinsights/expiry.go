package gitinsights

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/gittokens"
)

// ExpiringSuppression is a security suppression about to expire. The security package (B7)
// implements SuppressionSource over its table; until it exists nothing is scanned.
type ExpiringSuppression struct {
	ID        uuid.UUID
	ProjectID uuid.UUID
	Title     string
	ExpiresAt time.Time
}

// SuppressionSource lists suppressions that expire inside a window and have not been warned.
type SuppressionSource interface {
	ListExpiring(ctx context.Context, from, to time.Time, limit int) ([]ExpiringSuppression, error)
	MarkWarned(ctx context.Context, id uuid.UUID) error
}

var suppressionNS = uuid.MustParse("6f1c2b8e-3d54-4c0a-9a57-0d1d7b2c5e11")

// SuppressionExpiryScanner publishes security.suppression.expiring seven days ahead.
type SuppressionExpiryScanner struct {
	Source    SuppressionSource
	Publisher gitevents.Publisher
	Cfg       Config
	Log       *slog.Logger
	Now       func() time.Time
}

// Scan publishes one event per suppression not yet warned and returns how many. The event id is
// derived from the suppression and its expiry, so a retry after a failed MarkWarned is a no-op in
// the event store (and a changed expiry warns again).
func (s *SuppressionExpiryScanner) Scan(ctx context.Context) int {
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	warn := s.Cfg.SuppressionWarn
	if warn <= 0 {
		warn = 7 * 24 * time.Hour
	}
	list, err := s.Source.ListExpiring(ctx, now, now.Add(warn), 200)
	if err != nil {
		log.Warn("suppression expiry: listing failed", "error", err.Error())
		return 0
	}
	n := 0
	for _, x := range list {
		ev := gitevents.Event{
			ID:        uuid.NewSHA1(suppressionNS, []byte(x.ID.String()+"|"+x.ExpiresAt.UTC().Format(time.RFC3339))),
			ProjectID: x.ProjectID, Name: gitevents.SecuritySuppExpiring, Actor: "capsule",
			Data: map[string]any{"suppression_id": x.ID.String(), "title": firstLine(x.Title, 200), "expires_at": x.ExpiresAt.UTC().Format(time.RFC3339)},
		}
		if err := s.Publisher.Publish(ctx, ev); err != nil {
			log.Warn("suppression expiry: publish failed", "suppression", x.ID.String(), "error", err.Error())
			continue
		}
		if err := s.Source.MarkWarned(ctx, x.ID); err != nil {
			log.Warn("suppression expiry: marking warned failed", "suppression", x.ID.String(), "error", err.Error())
			continue
		}
		n++
	}
	return n
}

// Run scans every hour until ctx is done.
func (s *SuppressionExpiryScanner) Run(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Scan(ctx)
		}
	}
}

// TokenNoticeStore is what the token expiry notice needs: where to file the notification and the
// notification store itself.
type TokenNoticeStore interface {
	gitevents.NotifyStore
	// UserOrg returns the organization (and project, when the token names one) a notification of
	// the user is filed under. ok=false when the user belongs to no organization.
	UserOrg(ctx context.Context, userID uuid.UUID, projectIDs []uuid.UUID) (ref TokenOrgRef, ok bool, err error)
}

// TokenOrgRef locates the notification of a token notice.
type TokenOrgRef struct {
	OrgID       uuid.UUID
	ProjectID   *uuid.UUID
	OrgSlug     string
	ProjectSlug string
}

// TokenExpiryNotifier implements gittokens.Notifier: the in-app notice and, when the user has the
// email channel on, an email, seven days before a token expires. gittokens marks the token as
// warned afterwards, so this runs once per token.
type TokenExpiryNotifier struct {
	Store   TokenNoticeStore
	Mailer  gitevents.Mailer // may be nil
	BaseURL string
	Log     *slog.Logger
}

var _ gittokens.Notifier = (*TokenExpiryNotifier)(nil)

// TokenExpiring implements gittokens.Notifier.
func (n *TokenExpiryNotifier) TokenExpiring(ctx context.Context, t *gittokens.Token) error {
	ref, ok, err := n.Store.UserOrg(ctx, t.UserID, t.ProjectIDs)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	url := strings.TrimRight(n.BaseURL, "/") + "/settings/git/tokens"
	title := fmt.Sprintf("Tu token de acceso %q caduca el %s", oneLine(t.Name), t.ExpiresAt.UTC().Format("2006-01-02"))
	project := ref.OrgSlug
	if ref.ProjectSlug != "" {
		project += "/" + ref.ProjectSlug
	}
	st, err := n.Store.GetSettings(ctx, t.UserID)
	if err != nil {
		return err
	}
	chans := gitevents.EffectiveChannels(st, gitevents.SecuritySuppExpiring)
	has := func(c string) bool {
		for _, x := range chans {
			if x == c {
				return true
			}
		}
		return false
	}
	// A token notice has no event row; in-app is always filed (it is an account safety notice).
	if _, err := n.Store.InsertNotification(ctx, &gitevents.Notification{
		ID: uuid.New(), UserID: t.UserID, OrgID: ref.OrgID, ProjectID: ref.ProjectID,
		Event: "token.expiring", Title: title, URL: url, Project: project, CreatedAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	if has(gitevents.ChannelEmail) && n.Mailer != nil {
		emails, err := n.Store.UserEmails(ctx, []uuid.UUID{t.UserID})
		if err == nil && emails[t.UserID] != "" {
			subj, text, htm := gitevents.RenderEmail(gitevents.Summary{Title: title, URL: url, Level: "warning"})
			if err := n.Mailer.Send(ctx, []string{emails[t.UserID]}, subj, text, htm); err != nil && n.Log != nil {
				n.Log.Warn("token expiry email failed", "user_id", t.UserID.String(), "error", err.Error())
			}
		}
	}
	return nil
}

// ---- late binding ---------------------------------------------------------------------------
//
// The token service (A7) and the security package (B7) are wired independently of this package.
// These hooks let either order work: SharedTokenNotifier is always non-nil (a no-op until the
// wiring installs the real notifier) and SharedSuppressionSource lists nothing until B7 publishes
// its source with SetSuppressionSource.

var (
	lateMu     sync.RWMutex
	lateTokens gittokens.Notifier
	lateSupp   SuppressionSource
)

// SetTokenNotifier installs the notifier behind SharedTokenNotifier.
func SetTokenNotifier(n gittokens.Notifier) {
	lateMu.Lock()
	lateTokens = n
	lateMu.Unlock()
}

type lazyTokens struct{}

func (lazyTokens) TokenExpiring(ctx context.Context, t *gittokens.Token) error {
	lateMu.RLock()
	n := lateTokens
	lateMu.RUnlock()
	if n == nil {
		return errors.New("token expiry notifier not wired yet")
	}
	return n.TokenExpiring(ctx, t)
}

// SharedTokenNotifier is what the A7 wiring passes as gittokens Notifier. Until the notifier is
// installed it returns an error, so the token is not marked as warned and is retried.
func SharedTokenNotifier() gittokens.Notifier { return lazyTokens{} }

// SetSuppressionSource publishes the security package's source of expiring suppressions.
func SetSuppressionSource(s SuppressionSource) {
	lateMu.Lock()
	lateSupp = s
	lateMu.Unlock()
}

type lazySuppressions struct{}

func (lazySuppressions) ListExpiring(ctx context.Context, from, to time.Time, limit int) ([]ExpiringSuppression, error) {
	lateMu.RLock()
	s := lateSupp
	lateMu.RUnlock()
	if s == nil {
		return nil, nil
	}
	return s.ListExpiring(ctx, from, to, limit)
}

func (lazySuppressions) MarkWarned(ctx context.Context, id uuid.UUID) error {
	lateMu.RLock()
	s := lateSupp
	lateMu.RUnlock()
	if s == nil {
		return errors.New("suppression source not wired yet")
	}
	return s.MarkWarned(ctx, id)
}

// SharedSuppressionSource is the late-bound source the scanner reads.
func SharedSuppressionSource() SuppressionSource { return lazySuppressions{} }
