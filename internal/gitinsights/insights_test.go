package gitinsights

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitevents"
)

func TestMedianKnownCases(t *testing.T) {
	cases := []struct {
		in   []int64
		want int64
	}{
		{nil, 0}, {[]int64{7}, 7}, {[]int64{3, 1, 2}, 2}, {[]int64{4, 1, 3, 2}, 2}, // (2+3)/2 floors to 2
		{[]int64{10, 20}, 15}, {[]int64{100, 1, 1, 1, 1000}, 1}, {[]int64{5, 5, 5, 5}, 5},
	}
	for _, c := range cases {
		in := append([]int64(nil), c.in...)
		if got := Median(c.in); got != c.want {
			t.Errorf("Median(%v) = %d, want %d", in, got, c.want)
		}
		for i := range in {
			if in[i] != c.in[i] {
				t.Errorf("Median modified its input")
			}
		}
	}
}

func at(h int) time.Time {
	return time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(h) * time.Hour)
}

func TestComputePRStatsKnownCase(t *testing.T) {
	since, until := at(0), at(24*10)
	ev := []PREvent{
		// PR 1: opened h2, author's own review h3 (ignored), reviewer review h5, merged h10
		{1, TypePROpened, "ana", "ana", at(2)}, {1, TypePRReview, "ana", "ana", at(3)},
		{1, TypePRReview, "bob", "ana", at(5)}, {1, TypePRMerged, "ana", "ana", at(10)},
		// PR 2: opened h4, review h4+10h, merged h4+20h
		{2, TypePROpened, "bob", "bob", at(4)}, {2, TypePRReview, "ana", "bob", at(14)}, {2, TypePRMerged, "bob", "bob", at(24)},
		// PR 3: opened, never reviewed nor merged
		{3, TypePROpened, "ana", "ana", at(6)},
		// PR 4: opened before the window, merged inside it: counts as merged, no time to merge? opening is known
		{4, TypePROpened, "bob", "bob", at(-48)}, {4, TypePRMerged, "bob", "bob", at(1)},
		// PR 5: merged inside the window, opening unknown: merged count only
		{5, TypePRMerged, "ana", "ana", at(7)},
		// PR 6: review that arrives before the opening (out of order) is discarded
		{6, TypePROpened, "ana", "ana", at(8)}, {6, TypePRReview, "bob", "ana", at(7)},
	}
	st := ComputePRStats(ev, since, until)
	if st.Opened != 5-1 { // PRs 1,2,3,6 opened in window
		t.Fatalf("opened %d", st.Opened)
	}
	if st.Merged != 4 { // 1,2,4,5
		t.Fatalf("merged %d", st.Merged)
	}
	// first reviews: PR1 3h, PR2 10h => median (10800+36000)/2 = 23400
	if got := Median(st.ToFirstReview); got != 23400 || len(st.ToFirstReview) != 2 {
		t.Fatalf("first review %v median %d", st.ToFirstReview, got)
	}
	// time to merge: PR1 8h, PR2 20h, PR4 50h => median 20h = 72000
	if got := Median(st.ToMerge); got != 72000 || len(st.ToMerge) != 3 {
		t.Fatalf("merge %v median %d", st.ToMerge, got)
	}
}

type fakeStore struct {
	counts Counts
	pr     []PREvent
	rows   []Activity
}

func (f *fakeStore) Insert(_ context.Context, a *Activity) (bool, error) {
	if a.EventID != nil {
		for _, r := range f.rows {
			if r.EventID != nil && *r.EventID == *a.EventID {
				return false, nil
			}
		}
	}
	f.rows = append(f.rows, *a)
	return true, nil
}
func (f *fakeStore) List(context.Context, uuid.UUID, *Cursor, int) ([]Activity, error) {
	return nil, nil
}
func (f *fakeStore) Counts(context.Context, uuid.UUID, time.Time, time.Time) (Counts, error) {
	return f.counts, nil
}
func (f *fakeStore) PRTimeline(context.Context, uuid.UUID, time.Time, time.Time) ([]PREvent, error) {
	return f.pr, nil
}
func (f *fakeStore) PurgeBefore(context.Context, time.Time) (int64, error) { return 0, nil }

func TestInsightsAggregation(t *testing.T) {
	a, b := "ana", "bob"
	_ = a
	_ = b
	st := &fakeStore{counts: Counts{Commits: 9, DeploysOK: 7, DeploysFailed: 1,
		Contributors: []Contributor{{Login: "bob", Commits: 3}, {Login: "ana", Commits: 6}, {Login: "cy", Commits: 3}}},
		pr: []PREvent{{1, TypePROpened, "ana", "ana", at(1)}, {1, TypePRMerged, "ana", "ana", at(3)}}}
	s := &Service{Store: st}
	out, err := s.Insights(context.Background(), uuid.New(), at(0), at(100))
	if err != nil {
		t.Fatal(err)
	}
	if out.Commits != 9 || out.Deploys != 8 || out.ChangeFailureRate != 0.125 || out.PRsOpened != 1 || out.PRsMerged != 1 || out.MedianTimeToMerge != 7200 {
		t.Fatalf("%+v", out)
	}
	if out.Contributors[0].Person.Login != "ana" || out.Contributors[1].Person.Login != "bob" || out.Contributors[2].Person.Login != "cy" {
		t.Fatalf("order %+v", out.Contributors)
	}
	// no deployments: rate 0, not NaN
	st.counts = Counts{}
	out, _ = s.Insights(context.Background(), uuid.New(), at(0), at(100))
	if out.ChangeFailureRate != 0 || out.Deploys != 0 || out.Contributors == nil {
		t.Fatalf("%+v", out)
	}
}

func TestResolveWindow(t *testing.T) {
	now := at(24 * 100)
	s := &Service{Now: func() time.Time { return now }}
	f, u, err := s.ResolveWindow(nil, nil)
	if err != nil || !u.Equal(now) || !f.Equal(now.Add(-DefaultWindow)) {
		t.Fatalf("default: %v %v %v", f, u, err)
	}
	old := now.Add(-400 * 24 * time.Hour)
	if _, _, err := s.ResolveWindow(&old, nil); err == nil {
		t.Fatal("window over 366 days accepted")
	}
	fut := now.Add(time.Hour)
	if _, _, err := s.ResolveWindow(&fut, nil); err == nil {
		t.Fatal("since after until accepted")
	}
}

func TestFromEventAndRecorderIdempotent(t *testing.T) {
	pid, eid := uuid.New(), uuid.New()
	e := gitevents.Event{ID: eid, ProjectID: pid, OrgID: uuid.New(), Name: gitevents.PRReviewSubmitted, Actor: "bob", CreatedAt: at(1),
		Data: map[string]any{"pr": float64(12), "title": "Fix\nbug", "state": "approved", "author": "ana", "body": "secret text"}}
	a, ok := FromEvent(e)
	if !ok || a.Type != TypePRReview || a.PR != 12 || a.Ref != "#12" || a.Actor != "bob" || strings.Contains(a.Summary, "\n") {
		t.Fatalf("%+v", a)
	}
	if _, has := a.Data["body"]; has || a.Data["author"] != "ana" {
		t.Fatalf("data not whitelisted: %v", a.Data)
	}
	re, _ := FromEvent(gitevents.Event{Name: gitevents.PROpened, Data: map[string]any{"pr": 3, "reopened": true}})
	if re.Type != TypePRReopened {
		t.Fatal("reopened PRs must not count as opened")
	}
	if _, ok := FromEvent(gitevents.Event{Name: gitevents.CheckCompleted}); ok {
		t.Fatal("check statuses are not activity")
	}
	st := &fakeStore{}
	r := &ActivityRecorder{Store: st}
	for i := 0; i < 3; i++ {
		if err := r.Handle(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	if len(st.rows) != 1 {
		t.Fatalf("rows %d", len(st.rows))
	}
}

func TestEveryRecordedEventNameIsInCatalog(t *testing.T) {
	for _, n := range []string{gitevents.GitPush, gitevents.PROpened, gitevents.PRMerged, gitevents.DeploymentFailed, gitevents.ApprovalDecided, gitevents.SecurityAlertCreated} {
		if _, ok := FromEvent(gitevents.Event{Name: n}); !ok {
			t.Errorf("%s not mapped", n)
		}
	}
}

func TestRenderDigestEscapes(t *testing.T) {
	items := []gitevents.Notification{{Title: "<script>alert(1)</script>\nX", URL: "https://a/b?x=1&y=2", Project: "org/p"}}
	subj, text, htm := RenderDigest("daily", items, 3)
	if strings.Contains(htm, "<script>") || !strings.Contains(htm, "&lt;script&gt;") || !strings.Contains(htm, "y 2 mas") {
		t.Fatalf("html: %s", htm)
	}
	if strings.ContainsAny(subj, "\r\n") || !strings.Contains(text, "org/p") {
		t.Fatalf("subject/text: %q %q", subj, text)
	}
}

type digestStore struct {
	cands   []DigestCandidate
	pending int
	claims  map[uuid.UUID]bool
	claimed []uuid.UUID
}

func (d *digestStore) Candidates(context.Context, string, time.Time, int) ([]DigestCandidate, error) {
	return d.cands, nil
}
func (d *digestStore) Pending(context.Context, uuid.UUID, time.Time, int) ([]gitevents.Notification, int, error) {
	return []gitevents.Notification{{Title: "t"}}, d.pending, nil
}
func (d *digestStore) Claim(_ context.Context, id uuid.UUID, _ *time.Time, _ time.Time) (bool, error) {
	if d.claims[id] {
		return false, nil
	}
	d.claimed = append(d.claimed, id)
	return true, nil
}
func (d *digestStore) Release(context.Context, uuid.UUID, time.Time, *time.Time) error { return nil }

type mailRec struct{ to []string }

func (m *mailRec) Send(_ context.Context, to []string, _, _, _ string) error {
	m.to = append(m.to, to...)
	return nil
}

func TestDigestSchedule(t *testing.T) {
	u1, u2 := uuid.New(), uuid.New()
	ds := &digestStore{pending: 2, claims: map[uuid.UUID]bool{u2: true},
		cands: []DigestCandidate{{UserID: u1, Email: "a@x.io"}, {UserID: u2, Email: "b@x.io"}, {UserID: uuid.New(), Email: "not-an-email"}}}
	m := &mailRec{}
	now := time.Date(2026, 11, 3, 13, 0, 0, 0, time.UTC) // Tuesday, after 12:00 UTC
	d := &Digester{Store: ds, Mailer: m, Cfg: ConfigFromEnv(), Now: func() time.Time { return now }}
	if n := d.Tick(context.Background()); n != 1 || len(m.to) != 1 || m.to[0] != "a@x.io" {
		t.Fatalf("daily: sent %d to %v", n, m.to)
	}
	// before the digest hour nothing goes out
	m.to = nil
	ds.claimed = nil
	d.Now = func() time.Time { return time.Date(2026, 11, 3, 6, 0, 0, 0, time.UTC) }
	if n := d.Tick(context.Background()); n != 0 || len(ds.claimed) != 0 {
		t.Fatalf("early: %d", n)
	}
	// nothing pending: the period is consumed without an email
	ds.pending = 0
	d.Now = func() time.Time { return now }
	if n := d.Tick(context.Background()); n != 0 {
		t.Fatalf("empty digest sent %d", n)
	}
	// no mailer: disabled
	d.Mailer = nil
	if n := d.Tick(context.Background()); n != 0 {
		t.Fatal("sent without mailer")
	}
}

type suppSrc struct {
	list   []ExpiringSuppression
	warned []uuid.UUID
}

func (s *suppSrc) ListExpiring(context.Context, time.Time, time.Time, int) ([]ExpiringSuppression, error) {
	return s.list, nil
}
func (s *suppSrc) MarkWarned(_ context.Context, id uuid.UUID) error {
	s.warned = append(s.warned, id)
	return nil
}

type pubRec struct{ evs []gitevents.Event }

func (p *pubRec) Publish(_ context.Context, e gitevents.Event) error {
	p.evs = append(p.evs, e)
	return nil
}

func TestSuppressionExpiryDeterministicEventID(t *testing.T) {
	id, proj := uuid.New(), uuid.New()
	exp := at(48)
	src := &suppSrc{list: []ExpiringSuppression{{ID: id, ProjectID: proj, Title: "CVE-1", ExpiresAt: exp}}}
	pub := &pubRec{}
	s := &SuppressionExpiryScanner{Source: src, Publisher: pub, Now: func() time.Time { return at(0) }}
	if s.Scan(context.Background()) != 1 || s.Scan(context.Background()) != 1 {
		t.Fatal("scan count")
	}
	if len(pub.evs) != 2 || pub.evs[0].ID != pub.evs[1].ID || pub.evs[0].Name != gitevents.SecuritySuppExpiring {
		t.Fatalf("events %+v", pub.evs)
	}
	src.list[0].ExpiresAt = exp.Add(24 * time.Hour)
	s.Scan(context.Background())
	if pub.evs[2].ID == pub.evs[0].ID {
		t.Fatal("a new expiry must warn again")
	}
}
