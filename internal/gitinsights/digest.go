package gitinsights

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/mail"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitevents"
)

// Config of the package.
type Config struct {
	// DigestHourUTC is the hour (UTC) from which the daily digest of a day may go out
	// (CAPSULE_DIGEST_HOUR_UTC, default 12 = 07:00 in Lima).
	DigestHourUTC int
	// DigestWeekday is the day of the weekly digest (CAPSULE_DIGEST_WEEKDAY 0=Sunday..6, default 1 Monday).
	DigestWeekday time.Weekday
	// ActivityRetentionDays (CAPSULE_ACTIVITY_RETENTION_DAYS, default 400, minimum 90).
	ActivityRetentionDays int
	// SuppressionWarn is how long before expiry the notice goes out (7 days, SPEC 5.8).
	SuppressionWarn time.Duration
}

// ConfigFromEnv builds the configuration.
func ConfigFromEnv() Config {
	c := Config{DigestHourUTC: 12, DigestWeekday: time.Monday, ActivityRetentionDays: 400, SuppressionWarn: 7 * 24 * time.Hour}
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("CAPSULE_DIGEST_HOUR_UTC"))); err == nil && n >= 0 && n <= 23 {
		c.DigestHourUTC = n
	}
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("CAPSULE_DIGEST_WEEKDAY"))); err == nil && n >= 0 && n <= 6 {
		c.DigestWeekday = time.Weekday(n)
	}
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("CAPSULE_ACTIVITY_RETENTION_DAYS"))); err == nil {
		c.ActivityRetentionDays = n
	}
	if c.ActivityRetentionDays < 90 {
		c.ActivityRetentionDays = 90
	}
	return c
}

// DigestCandidate is a user whose digest may be due.
type DigestCandidate struct {
	UserID   uuid.UUID
	Email    string
	LastSent *time.Time
}

// DigestStore is what the digest needs from the database.
type DigestStore interface {
	// Candidates returns users with the given digest mode (daily|weekly) whose last digest is
	// before boundary (or never sent).
	Candidates(ctx context.Context, mode string, boundary time.Time, limit int) ([]DigestCandidate, error)
	// Pending returns the unread notifications of the user created after since (newest first,
	// at most limit) and the total count.
	Pending(ctx context.Context, userID uuid.UUID, since time.Time, limit int) ([]gitevents.Notification, int, error)
	// Claim records now as the last digest of the user when it is still prev (compare and set);
	// claimed=false means another instance got there first.
	Claim(ctx context.Context, userID uuid.UUID, prev *time.Time, now time.Time) (claimed bool, err error)
	// Release restores prev after a failed send (best effort).
	Release(ctx context.Context, userID uuid.UUID, now time.Time, prev *time.Time) error
}

// Digester sends the daily and weekly notification digest by email, at most once per period and
// user. Without a mailer nothing is sent.
type Digester struct {
	Store  DigestStore
	Mailer gitevents.Mailer
	Cfg    Config
	Log    *slog.Logger
	Now    func() time.Time

	warnOnce sync.Once
}

const digestMaxItems = 50

func (d *Digester) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

func (d *Digester) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

// boundary is the start of the period the digest at now belongs to, or ok=false when the mode is
// not due yet (before the digest hour, or not the weekly day).
func (d *Digester) boundary(mode string, now time.Time) (time.Time, bool) {
	day := time.Date(now.Year(), now.Month(), now.Day(), d.Cfg.DigestHourUTC, 0, 0, 0, time.UTC)
	if now.Before(day) {
		return time.Time{}, false
	}
	if mode == "weekly" && now.Weekday() != d.Cfg.DigestWeekday {
		return time.Time{}, false
	}
	return day, true
}

// Tick runs one pass for both modes and returns how many emails were sent.
func (d *Digester) Tick(ctx context.Context) int {
	if d.Mailer == nil {
		d.warnOnce.Do(func() {
			d.log().Warn("notification digest disabled: no mailer configured (set CAPSULE_NOTIFY_FROM_EMAIL)")
		})
		return 0
	}
	sent := 0
	now := d.now()
	for _, mode := range []string{"daily", "weekly"} {
		b, ok := d.boundary(mode, now)
		if !ok {
			continue
		}
		span := 24 * time.Hour
		if mode == "weekly" {
			span = 7 * 24 * time.Hour
		}
		cands, err := d.Store.Candidates(ctx, mode, b, 500)
		if err != nil {
			d.log().Warn("digest: listing candidates failed", "mode", mode, "error", err.Error())
			continue
		}
		for _, c := range cands {
			if ctx.Err() != nil {
				return sent
			}
			ok, err := d.Store.Claim(ctx, c.UserID, c.LastSent, now)
			if err != nil || !ok {
				continue
			}
			since := now.Add(-span)
			if c.LastSent != nil && c.LastSent.After(since) {
				since = *c.LastSent
			}
			items, total, err := d.Store.Pending(ctx, c.UserID, since, digestMaxItems)
			if err != nil || total == 0 {
				continue // nothing to say: the period is consumed without an email
			}
			if _, err := mail.ParseAddress(c.Email); err != nil || c.Email == "" {
				continue
			}
			subject, text, htm := RenderDigest(mode, items, total)
			if err := d.Mailer.Send(ctx, []string{c.Email}, subject, text, htm); err != nil {
				d.log().Warn("digest: email failed", "user_id", c.UserID.String(), "error", err.Error())
				_ = d.Store.Release(ctx, c.UserID, now, c.LastSent)
				continue
			}
			sent++
		}
	}
	return sent
}

// Run ticks every 15 minutes until ctx is done.
func (d *Digester) Run(ctx context.Context) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.Tick(ctx)
		}
	}
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)), " ")
}

// RenderDigest renders the fixed digest email: subject, plain text and HTML (user text escaped).
func RenderDigest(mode string, items []gitevents.Notification, total int) (subject, text, htmlBody string) {
	period := "diario"
	if mode == "weekly" {
		period = "semanal"
	}
	subject = fmt.Sprintf("[Git Capsule] Resumen %s: %d novedades sin leer", period, total)
	groups := map[string][]gitevents.Notification{}
	for _, n := range items {
		groups[n.Project] = append(groups[n.Project], n)
	}
	projects := make([]string, 0, len(groups))
	for p := range groups {
		projects = append(projects, p)
	}
	sort.Strings(projects)
	var t, h strings.Builder
	fmt.Fprintf(&t, "Resumen %s de Git Capsule: %d novedades sin leer.\n", period, total)
	fmt.Fprintf(&h, "<div style=\"font-family:system-ui,sans-serif;font-size:14px;color:#111\"><p style=\"font-size:16px;font-weight:600\">Resumen %s de Git Capsule: %d novedades sin leer</p>", period, total)
	for _, p := range projects {
		name := p
		if name == "" {
			name = "General"
		}
		fmt.Fprintf(&t, "\n%s\n", oneLine(name))
		fmt.Fprintf(&h, "<p style=\"font-weight:600;margin-bottom:2px\">%s</p><ul>", html.EscapeString(oneLine(name)))
		for _, n := range groups[p] {
			line := oneLine(n.Title)
			fmt.Fprintf(&t, "- %s", line)
			if n.URL != "" {
				fmt.Fprintf(&t, " (%s)", n.URL)
			}
			t.WriteString("\n")
			if n.URL != "" {
				fmt.Fprintf(&h, "<li><a href=\"%s\">%s</a></li>", html.EscapeString(n.URL), html.EscapeString(line))
			} else {
				fmt.Fprintf(&h, "<li>%s</li>", html.EscapeString(line))
			}
		}
		h.WriteString("</ul>")
	}
	if total > len(items) {
		more := total - len(items)
		fmt.Fprintf(&t, "\ny %d mas en tu bandeja.\n", more)
		fmt.Fprintf(&h, "<p>y %d mas en tu bandeja.</p>", more)
	}
	t.WriteString("\nRecibes este resumen por tus preferencias de notificaciones de Git Capsule.\n")
	h.WriteString("<p style=\"color:#666;font-size:12px\">Recibes este resumen por tus preferencias de notificaciones de Git Capsule.</p></div>")
	return subject, t.String(), h.String()
}
