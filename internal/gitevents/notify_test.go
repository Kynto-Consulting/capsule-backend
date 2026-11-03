package gitevents

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func notifRig(t *testing.T) (*Notifier, *memNotify, *fakeMailer) {
	t.Helper()
	st := newMemNotify()
	m := &fakeMailer{}
	return NewNotifier(st, m, "https://app.example.com", nil), st, m
}

func ev(name string, data map[string]any) Event {
	return Event{ID: uuid.New(), OrgID: uuid.New(), ProjectID: uuid.New(), OrgSlug: "acme", ProjectSlug: "shop", Name: name, Actor: "ana", Data: data, CreatedAt: time.Now()}
}

func TestRecipientsPolicy(t *testing.T) {
	n, st, _ := notifRig(t)
	ctx := context.Background()
	author, reviewer, admin1, admin2, requester := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	st.logins = map[string]uuid.UUID{"ana": author, "bruno": reviewer}
	st.admins = []uuid.UUID{admin1, admin2, admin1}

	cases := []struct {
		name string
		e    Event
		want []uuid.UUID
	}{
		{"review goes to the PR author", ev(PRReviewSubmitted, map[string]any{"author": "ana"}), []uuid.UUID{author}},
		{"merged goes to the author", ev(PRMerged, map[string]any{"author": "ana"}), []uuid.UUID{author}},
		{"review requested goes to the reviewer", ev(PRReviewRequested, map[string]any{"requested_reviewer": "bruno"}), []uuid.UUID{reviewer}},
		{"unknown login nobody", ev(PRReviewSubmitted, map[string]any{"author": "ghost"}), nil},
		{"deployment failed to admins", ev(DeploymentFailed, nil), []uuid.UUID{admin1, admin2}},
		{"security alert to admins", ev(SecurityAlertCreated, nil), []uuid.UUID{admin1, admin2}},
		{"decision to requester", ev(ApprovalDecided, map[string]any{"requested_by": requester.String()}), []uuid.UUID{requester}},
		{"decision without requester to admins", ev(ApprovalDecided, nil), []uuid.UUID{admin1, admin2}},
		{"backup ok is quiet", ev(BackupCompleted, map[string]any{"status": "success"}), nil},
		{"backup failed to admins", ev(BackupCompleted, map[string]any{"status": "failed"}), []uuid.UUID{admin1, admin2}},
		{"push is quiet", ev(GitPush, nil), nil},
		{"pr opened is quiet", ev(PROpened, nil), nil},
	}
	for _, c := range cases {
		got, err := n.Recipients(ctx, c.e)
		if err != nil {
			t.Fatal(err)
		}
		if !sameIDs(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	// Explicit recipients win over the policy; the actor is never notified of their own action.
	explicit := ev(ApprovalRequested, nil)
	explicit.Recipients = []uuid.UUID{requester, admin1}
	explicit.ActorUserID = admin1
	got, _ := n.Recipients(ctx, explicit)
	if !sameIDs(got, []uuid.UUID{requester}) {
		t.Fatalf("explicit minus actor: %v", got)
	}
}

func sameIDs(a, b []uuid.UUID) bool {
	m := map[uuid.UUID]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestEffectiveChannels(t *testing.T) {
	st := DefaultSettings()
	if got := EffectiveChannels(st, PRMerged); strings.Join(got, ",") != "in_app" {
		t.Fatalf("defaults: %v", got)
	}
	st.Channels = ChannelFlags{InApp: true, Email: true, SlackDM: false}
	if got := EffectiveChannels(st, PRMerged); strings.Join(got, ",") != "in_app,email" {
		t.Fatalf("channels on: %v", got)
	}
	st.Events = map[string][]string{PRMerged: {"email"}, PRClosed: {}}
	if got := EffectiveChannels(st, PRMerged); strings.Join(got, ",") != "email" {
		t.Fatalf("narrowed: %v", got)
	}
	if got := EffectiveChannels(st, PRClosed); len(got) != 0 {
		t.Fatalf("muted event: %v", got)
	}
	st.Events = map[string][]string{PRMerged: {"slack_dm"}}
	if got := EffectiveChannels(st, PRMerged); len(got) != 0 {
		t.Fatalf("a channel that is off globally never fires: %v", got)
	}
}

func TestNotifierHandleCreatesInboxEmailAndIsIdempotent(t *testing.T) {
	n, st, mail := notifRig(t)
	ctx := context.Background()
	admin := uuid.New()
	st.admins = []uuid.UUID{admin}
	st.emails[admin] = "admin@example.com"
	st.settings[admin] = Settings{Channels: ChannelFlags{InApp: true, Email: true}, Events: map[string][]string{}, Digest: "off"}

	e := ev(DeploymentFailed, map[string]any{"error": "boom"})
	for i := 0; i < 3; i++ { // the sweeper may redeliver the same event
		if err := n.Handle(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if len(st.rows) != 1 {
		t.Fatalf("one inbox row per (user, event), got %d", len(st.rows))
	}
	row := st.rows[0]
	if row.Event != DeploymentFailed || row.Project != "acme/shop" || !strings.Contains(row.Title, "Despliegue fallido") || !strings.HasPrefix(row.URL, "https://app.example.com/git/acme/shop") {
		t.Fatalf("%+v", row)
	}
	if len(mail.sent) != 1 || mail.sent[0].To[0] != "admin@example.com" {
		t.Fatalf("email must be sent once, got %+v", mail.sent)
	}
	if !strings.HasPrefix(mail.sent[0].Subject, "[Git Capsule] ") {
		t.Fatalf("subject: %q", mail.sent[0].Subject)
	}
}

func TestNotifierRespectsPreferences(t *testing.T) {
	n, st, mail := notifRig(t)
	ctx := context.Background()
	a, b := uuid.New(), uuid.New()
	st.admins = []uuid.UUID{a, b}
	st.emails[a], st.emails[b] = "a@x.io", "b@x.io"
	st.settings[a] = Settings{Channels: ChannelFlags{InApp: false, Email: true}, Events: map[string][]string{}, Digest: "off"} // email only
	st.settings[b] = Settings{Channels: ChannelFlags{InApp: true}, Events: map[string][]string{SecurityAlertCreated: {}}, Digest: "off"}
	if err := n.Handle(ctx, ev(SecurityAlertCreated, nil)); err != nil {
		t.Fatal(err)
	}
	if len(st.rows) != 0 {
		t.Fatalf("a has in_app off and b muted the event: %d rows", len(st.rows))
	}
	if len(mail.sent) != 1 || mail.sent[0].To[0] != "a@x.io" {
		t.Fatalf("only a wants email: %+v", mail.sent)
	}
}

func TestNotifierStoreFailureIsRetriedAndNoMailerIsQuiet(t *testing.T) {
	n, st, _ := notifRig(t)
	admin := uuid.New()
	st.admins = []uuid.UUID{admin}
	st.failIns = true
	if err := n.Handle(context.Background(), ev(DeploymentFailed, nil)); err == nil {
		t.Fatal("a storage failure must be returned so the bus retries")
	}
	st.failIns = false
	st.settings[admin] = Settings{Channels: ChannelFlags{InApp: true, Email: true}, Events: map[string][]string{}, Digest: "off"}
	n2 := NewNotifier(st, nil, "", nil) // no mailer configured
	if err := n2.Handle(context.Background(), ev(DeploymentFailed, nil)); err != nil {
		t.Fatalf("missing mailer must not fail the event: %v", err)
	}
	if len(st.rows) != 1 {
		t.Fatalf("inbox still works without email: %d", len(st.rows))
	}
}

func TestNotifierMailerFailureDoesNotFailTheEvent(t *testing.T) {
	n, st, mail := notifRig(t)
	admin := uuid.New()
	st.admins = []uuid.UUID{admin}
	st.emails[admin] = "a@x.io"
	st.settings[admin] = Settings{Channels: ChannelFlags{InApp: true, Email: true}, Events: map[string][]string{}, Digest: "off"}
	mail.fails = true
	if err := n.Handle(context.Background(), ev(DeploymentFailed, nil)); err != nil {
		t.Fatalf("%v", err)
	}
}

func TestValidateSettings(t *testing.T) {
	ok, err := ValidateSettings(Settings{Channels: ChannelFlags{InApp: true}, Events: map[string][]string{PRMerged: {"in_app", "in_app", "email"}}})
	if err != nil || ok.Digest != "off" || strings.Join(ok.Events[PRMerged], ",") != "in_app,email" {
		t.Fatalf("%+v %v", ok, err)
	}
	for name, in := range map[string]Settings{
		"digest":  {Digest: "hourly"},
		"event":   {Events: map[string][]string{"nope": {"in_app"}}},
		"channel": {Events: map[string][]string{PRMerged: {"sms"}}},
	} {
		if _, err := ValidateSettings(in); !errors.Is(err, ErrInvalidSettings) {
			t.Errorf("%s must be rejected: %v", name, err)
		}
	}
}

func TestInboxPaginationAndMark(t *testing.T) {
	n, st, _ := notifRig(t)
	ctx := context.Background()
	me, other := uuid.New(), uuid.New()
	base := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 5; i++ {
		st.rows = append(st.rows, Notification{ID: uuid.New(), UserID: me, Event: PRMerged, Title: "t", CreatedAt: base.Add(time.Duration(i) * time.Second)})
	}
	st.rows = append(st.rows, Notification{ID: uuid.New(), UserID: other, Event: PRMerged, CreatedAt: base})

	var seen []uuid.UUID
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		rows, next, err := n.List(ctx, me, false, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			seen = append(seen, r.ID)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 5 {
		t.Fatalf("pagination must visit every row exactly once, saw %d", len(seen))
	}
	uniq := map[uuid.UUID]bool{}
	for _, id := range seen {
		uniq[id] = true
	}
	if len(uniq) != 5 {
		t.Fatal("duplicates across pages")
	}

	if err := n.Mark(ctx, me, seen[:2], false); err != nil {
		t.Fatal(err)
	}
	rows, _, _ := n.List(ctx, me, true, "", 100)
	if len(rows) != 3 {
		t.Fatalf("unread after marking 2: %d", len(rows))
	}
	// marking another user's id is a no-op
	if err := n.Mark(ctx, other, seen[2:3], false); err != nil {
		t.Fatal(err)
	}
	if rows, _, _ = n.List(ctx, me, true, "", 100); len(rows) != 3 {
		t.Fatal("a user must not be able to mark someone else's notification")
	}
	if err := n.Mark(ctx, me, nil, true); err != nil {
		t.Fatal(err)
	}
	if rows, _, _ = n.List(ctx, me, true, "", 100); len(rows) != 0 {
		t.Fatalf("all read: %d", len(rows))
	}
	if _, _, err := n.List(ctx, me, false, "not-a-cursor", 10); err == nil {
		t.Fatal("bad cursor must fail")
	}
}

func TestCursorRoundTrip(t *testing.T) {
	c := Cursor{At: time.Now().UTC().Truncate(time.Microsecond), ID: uuid.New()}
	got, err := ParseCursor(c.Encode())
	if err != nil || !got.At.Equal(c.At) || got.ID != c.ID {
		t.Fatalf("%+v %v", got, err)
	}
	if c, err := ParseCursor(""); c != nil || err != nil {
		t.Fatal("empty cursor is the first page")
	}
	for _, bad := range []string{"%%%", "YWJj", "MXx4"} {
		if _, err := ParseCursor(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestDescribeCoversEveryCatalogEvent(t *testing.T) {
	for _, name := range Names() {
		e := ev(name, map[string]any{"pr": 7, "title": "T", "state": "approved", "reviewer": "b", "branch": "main", "context": "c", "conclusion": "failure"})
		sum := Describe("https://app.example.com", e)
		if strings.TrimSpace(sum.Title) == "" || strings.Contains(sum.Title, name+" en") {
			t.Errorf("%s has no dedicated description: %q", name, sum.Title)
		}
		if sum.URL == "" || !strings.HasPrefix(sum.URL, "https://app.example.com/") {
			t.Errorf("%s: link %q", name, sum.URL)
		}
	}
	if sum := Describe("", ev(PRMerged, nil)); sum.URL != "" {
		t.Fatal("no base URL -> no link")
	}
	for _, word := range []string{"demo", "simulado", "ficticio"} {
		for _, name := range Names() {
			if s := Describe("", ev(name, nil)); strings.Contains(strings.ToLower(s.Title+s.Body), word) {
				t.Fatalf("visible text must not say %q: %s", word, s.Title)
			}
		}
	}
}

func TestRenderEmailEscapesAndStripsHeaders(t *testing.T) {
	sum := Summary{Title: "PR <script>alert(1)</script>\r\nBcc: evil@x.io", Body: "<b>hi</b> & bye", URL: `https://a/b?x="1"&y=2`}
	subject, text, html := RenderEmail(sum)
	if strings.ContainsAny(subject, "\r\n") || strings.Contains(subject, "\n") {
		t.Fatalf("subject must be a single line: %q", subject)
	}
	if strings.Contains(html, "<script>") || strings.Contains(html, "<b>") || !strings.Contains(html, "&lt;script&gt;") || !strings.Contains(html, "&amp; bye") {
		t.Fatalf("html must escape user text: %s", html)
	}
	if strings.Contains(html, `href="https://a/b?x="1"`) {
		t.Fatalf("url must be escaped inside the attribute: %s", html)
	}
	if !strings.Contains(text, "Ver en Git Capsule") {
		t.Fatalf("text: %s", text)
	}
}
