package gitevents

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Channels a notification can use.
const (
	ChannelInApp   = "in_app"
	ChannelEmail   = "email"
	ChannelSlackDM = "slack_dm"
)

var validChannels = map[string]bool{ChannelInApp: true, ChannelEmail: true, ChannelSlackDM: true}

// Notification is one row of the in-app inbox.
type Notification struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"-"`
	OrgID     uuid.UUID  `json:"-"`
	ProjectID *uuid.UUID `json:"-"`
	EventID   *uuid.UUID `json:"-"`
	Event     string     `json:"event"`
	Title     string     `json:"title"`
	URL       string     `json:"url"`
	Project   string     `json:"project"` // "org/project"
	Read      bool       `json:"read"`
	CreatedAt time.Time  `json:"created_at"`
}

// Settings are the per-user preferences. Channels switches a channel on or off for everything;
// Events narrows the channels of one event (absent event = every enabled channel).
type Settings struct {
	Channels ChannelFlags        `json:"channels"`
	Events   map[string][]string `json:"events"`
	Digest   string              `json:"digest"` // off | daily | weekly (sent by package C2)
}

// ChannelFlags mirrors NotificationSettings.channels of the API.
type ChannelFlags struct {
	InApp   bool `json:"in_app"`
	Email   bool `json:"email"`
	SlackDM bool `json:"slack_dm"`
}

// DefaultSettings: in-app on, email and Slack DM off, no digest.
func DefaultSettings() Settings {
	return Settings{Channels: ChannelFlags{InApp: true}, Events: map[string][]string{}, Digest: "off"}
}

// ErrInvalidSettings is wrapped by ValidateSettings errors.
var ErrInvalidSettings = errors.New("invalid notification settings")

// ValidateSettings checks s and normalizes it (nil maps, duplicate channels).
func ValidateSettings(in Settings) (Settings, error) {
	out := Settings{Channels: in.Channels, Events: map[string][]string{}, Digest: in.Digest}
	if out.Digest == "" {
		out.Digest = "off"
	}
	switch out.Digest {
	case "off", "daily", "weekly":
	default:
		return out, fmt.Errorf("%w: digest must be off, daily or weekly", ErrInvalidSettings)
	}
	for ev, chans := range in.Events {
		if !Valid(ev) {
			return out, fmt.Errorf("%w: unknown event %q", ErrInvalidSettings, ev)
		}
		seen := map[string]bool{}
		list := []string{}
		for _, c := range chans {
			if !validChannels[c] {
				return out, fmt.Errorf("%w: unknown channel %q", ErrInvalidSettings, c)
			}
			if !seen[c] {
				seen[c] = true
				list = append(list, c)
			}
		}
		out.Events[ev] = list
	}
	return out, nil
}

// NotifyStore persists the inbox and preferences and answers the recipient questions
// (implemented in internal/repository, table notifications / notification_settings).
type NotifyStore interface {
	// InsertNotification stores n; inserted=false when (user_id, event_id) already exists.
	InsertNotification(ctx context.Context, n *Notification) (inserted bool, err error)
	// ListNotifications returns up to limit rows newest first, after the cursor (nil = start).
	ListNotifications(ctx context.Context, userID uuid.UUID, unreadOnly bool, after *Cursor, limit int) ([]Notification, error)
	MarkRead(ctx context.Context, userID uuid.UUID, ids []uuid.UUID) error
	MarkAllRead(ctx context.Context, userID uuid.UUID) error
	// GetSettings returns the stored settings or DefaultSettings() when none.
	GetSettings(ctx context.Context, userID uuid.UUID) (Settings, error)
	PutSettings(ctx context.Context, userID uuid.UUID, s Settings) error
	SettingsFor(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]Settings, error)
	// ProjectAdmins are the project admins plus the org owners and admins.
	ProjectAdmins(ctx context.Context, orgID, projectID uuid.UUID) ([]uuid.UUID, error)
	// UsersByLogin maps Forgejo logins to Capsule users (via git_identities); unknown logins are absent.
	UsersByLogin(ctx context.Context, logins []string) (map[string]uuid.UUID, error)
	UserEmails(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error)
}

// Mailer sends a plain notification email. Implemented over SES by package webhookout.
type Mailer interface {
	Send(ctx context.Context, to []string, subject, text, html string) error
}

// DMSender delivers a Slack direct message to a Capsule user. No implementation is wired: it
// needs a Slack app with a bot token, which Capsule does not have yet. When nil the slack_dm
// channel is accepted as a preference and skipped.
type DMSender interface {
	SendDM(ctx context.Context, userID uuid.UUID, text string) error
}

// Cursor is the decoded form of the opaque next_cursor of the inbox.
type Cursor struct {
	At time.Time
	ID uuid.UUID
}

// Encode renders the cursor as an opaque string.
func (c Cursor) Encode() string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(c.At.UnixMicro(), 10) + "|" + c.ID.String()))
}

// ParseCursor decodes a cursor produced by Encode ("" = nil, nil).
func ParseCursor(s string) (*Cursor, error) {
	if s == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid cursor")
	}
	a, b, ok := strings.Cut(string(raw), "|")
	if !ok {
		return nil, errors.New("invalid cursor")
	}
	us, err := strconv.ParseInt(a, 10, 64)
	if err != nil {
		return nil, errors.New("invalid cursor")
	}
	id, err := uuid.Parse(b)
	if err != nil {
		return nil, errors.New("invalid cursor")
	}
	return &Cursor{At: time.UnixMicro(us).UTC(), ID: id}, nil
}

// Notifier is the Subscriber that creates in-app notifications and emails, and the service
// behind /user/notifications and /user/notification-settings.
type Notifier struct {
	store   NotifyStore
	mailer  Mailer // may be nil: the email channel is skipped
	dm      DMSender
	baseURL string
	log     *slog.Logger

	warnOnce sync.Once
}

// NewNotifier builds the notifier. baseURL is the frontend origin for links.
func NewNotifier(store NotifyStore, mailer Mailer, baseURL string, log *slog.Logger) *Notifier {
	if log == nil {
		log = slog.Default()
	}
	return &Notifier{store: store, mailer: mailer, baseURL: strings.TrimRight(baseURL, "/"), log: log}
}

// SetDMSender installs a Slack DM sender (optional).
func (n *Notifier) SetDMSender(d DMSender) { n.dm = d }

// Name implements Subscriber.
func (n *Notifier) Name() string { return "notifications" }

var _ Subscriber = (*Notifier)(nil)

// Recipients decides who should hear about e (before preferences). Explicit recipients win;
// otherwise the event data names the people: author, requested_reviewer (Forgejo logins, mapped
// through git_identities) or requested_by (a Capsule user id), and operational events go to the
// project admins. Events not listed notify nobody.
func (n *Notifier) Recipients(ctx context.Context, e Event) ([]uuid.UUID, error) {
	set := map[uuid.UUID]bool{}
	add := func(ids ...uuid.UUID) {
		for _, id := range ids {
			if id != uuid.Nil && id != e.ActorUserID {
				set[id] = true
			}
		}
	}
	if len(e.Recipients) > 0 {
		add(e.Recipients...)
	} else {
		var logins []string
		admins := false
		switch e.Name {
		case PRReviewSubmitted, PRMerged, PRClosed:
			logins = append(logins, s(e, "author"))
		case PRReviewRequested:
			logins = append(logins, s(e, "requested_reviewer"))
		case ApprovalDecided:
			if id, err := uuid.Parse(s(e, "requested_by")); err == nil {
				add(id)
			} else {
				admins = true
			}
		case DeploymentFailed, SecurityAlertCreated, SecurityPolicyBlock, SecuritySuppExpiring,
			ProtectionChanged, MemberChanged, RecoveryCompleted:
			admins = true
		case BackupCompleted:
			admins = s(e, "status") == "failed"
		}
		if logins = nonEmpty(logins); len(logins) > 0 {
			m, err := n.store.UsersByLogin(ctx, logins)
			if err != nil {
				return nil, err
			}
			for _, id := range m {
				add(id)
			}
		}
		if admins {
			ids, err := n.store.ProjectAdmins(ctx, e.OrgID, e.ProjectID)
			if err != nil {
				return nil, err
			}
			add(ids...)
		}
	}
	out := make([]uuid.UUID, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

func nonEmpty(in []string) []string {
	var out []string
	for _, v := range in {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// EffectiveChannels intersects the channels enabled globally with those chosen for the event.
func EffectiveChannels(st Settings, event string) []string {
	enabled := map[string]bool{ChannelInApp: st.Channels.InApp, ChannelEmail: st.Channels.Email, ChannelSlackDM: st.Channels.SlackDM}
	want := []string{ChannelInApp, ChannelEmail, ChannelSlackDM}
	if chosen, ok := st.Events[event]; ok {
		want = chosen
	}
	var out []string
	for _, c := range want {
		if enabled[c] {
			out = append(out, c)
		}
	}
	return out
}

// Handle implements Subscriber. It is idempotent: the inbox row is unique per (user, event) and
// an email is only sent along with a newly created inbox row (or, with the in-app channel off,
// once per dispatch).
func (n *Notifier) Handle(ctx context.Context, e Event) error {
	ids, err := n.Recipients(ctx, e)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	settings, err := n.store.SettingsFor(ctx, ids)
	if err != nil {
		return err
	}
	sum := Describe(n.baseURL, e)
	var emailTo []uuid.UUID
	var firstErr error
	for _, id := range ids {
		st, ok := settings[id]
		if !ok {
			st = DefaultSettings()
		}
		chans := EffectiveChannels(st, e.Name)
		inserted := true
		hasInApp := false
		for _, c := range chans {
			if c == ChannelInApp {
				hasInApp = true
			}
		}
		if hasInApp {
			pid := e.ProjectID
			eid := e.ID
			var evPtr *uuid.UUID
			if eid != uuid.Nil {
				evPtr = &eid
			}
			ins, err := n.store.InsertNotification(ctx, &Notification{
				ID: uuid.New(), UserID: id, OrgID: e.OrgID, ProjectID: &pid, EventID: evPtr,
				Event: e.Name, Title: trunc(sum.Title, 300), URL: sum.URL,
				Project: e.OrgSlug + "/" + e.ProjectSlug, CreatedAt: time.Now().UTC(),
			})
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			inserted = ins
		}
		for _, c := range chans {
			switch c {
			case ChannelEmail:
				if inserted {
					emailTo = append(emailTo, id)
				}
			case ChannelSlackDM:
				if n.dm != nil && inserted {
					if err := n.dm.SendDM(ctx, id, sum.Title+"\n"+sum.URL); err != nil {
						n.log.Warn("notifications: slack dm failed", "user_id", id, "error", err)
					}
				}
			}
		}
	}
	n.sendEmails(ctx, emailTo, sum)
	return firstErr
}

func (n *Notifier) sendEmails(ctx context.Context, users []uuid.UUID, sum Summary) {
	if len(users) == 0 {
		return
	}
	if n.mailer == nil {
		n.warnOnce.Do(func() {
			n.log.Warn("notifications: email channel requested but no mailer is configured (set CAPSULE_NOTIFY_FROM_EMAIL)")
		})
		return
	}
	emails, err := n.store.UserEmails(ctx, users)
	if err != nil {
		n.log.Warn("notifications: loading recipient emails failed", "error", err)
		return
	}
	subject, text, html := RenderEmail(sum)
	for _, id := range users {
		addr := emails[id]
		if _, err := mail.ParseAddress(addr); err != nil || addr == "" {
			continue
		}
		if err := n.mailer.Send(ctx, []string{addr}, subject, text, html); err != nil {
			n.log.Warn("notifications: email failed", "user_id", id, "error", err)
		}
	}
}

// ---- API-facing operations ---------------------------------------------------------------------

// List returns the inbox page and the next cursor ("" when there is no more).
func (n *Notifier) List(ctx context.Context, userID uuid.UUID, unreadOnly bool, cursor string, limit int) ([]Notification, string, error) {
	cur, err := ParseCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 30
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := n.store.ListNotifications(ctx, userID, unreadOnly, cur, limit+1)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next = Cursor{At: last.CreatedAt, ID: last.ID}.Encode()
	}
	return rows, next, nil
}

// Mark marks the given notifications (or all) of the user as read.
func (n *Notifier) Mark(ctx context.Context, userID uuid.UUID, ids []uuid.UUID, all bool) error {
	if all {
		return n.store.MarkAllRead(ctx, userID)
	}
	if len(ids) == 0 {
		return nil
	}
	return n.store.MarkRead(ctx, userID, ids)
}

// Settings returns the user's preferences (defaults when never saved).
func (n *Notifier) Settings(ctx context.Context, userID uuid.UUID) (Settings, error) {
	return n.store.GetSettings(ctx, userID)
}

// SaveSettings validates and stores the preferences and returns them.
func (n *Notifier) SaveSettings(ctx context.Context, userID uuid.UUID, in Settings) (Settings, error) {
	st, err := ValidateSettings(in)
	if err != nil {
		return st, err
	}
	if err := n.store.PutSettings(ctx, userID, st); err != nil {
		return st, err
	}
	return st, nil
}

var (
	sharedNotifierMu sync.RWMutex
	sharedNotifier   *Notifier
)

// SetSharedNotifier publishes the notifier for the HTTP handlers (called by the wiring).
func SetSharedNotifier(n *Notifier) {
	sharedNotifierMu.Lock()
	sharedNotifier = n
	sharedNotifierMu.Unlock()
}

// SharedNotifier returns the notifier published by the wiring (nil before that).
func SharedNotifier() *Notifier {
	sharedNotifierMu.RLock()
	defer sharedNotifierMu.RUnlock()
	return sharedNotifier
}
