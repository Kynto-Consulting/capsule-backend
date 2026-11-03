package gitaudit

import (
	"bytes"
	"context"
	"encoding/csv"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNeutralizeCell(t *testing.T) {
	cases := map[string]string{
		"=1+1": "'=1+1", "+SUM(A1)": "'+SUM(A1)", "-2+3": "'-2+3", "@cmd": "'@cmd",
		"  =HYPERLINK(\"x\")": "'  =HYPERLINK(\"x\")", "\t=1": "'\t=1", "\r1": "'\r1",
		"normal": "normal", "": "", "git.push": "git.push", "{\"a\":1}": "{\"a\":1}",
	}
	for in, want := range cases {
		if got := NeutralizeCell(in); got != want {
			t.Errorf("NeutralizeCell(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:5678": "1.2.3.4", "[::1]:80": "::1", "::1": "::1", "10.0.0.1": "10.0.0.1",
		"[fe80::1%eth0]:1": "fe80::1", "garbage": "", "": "", "::ffff:1.2.3.4": "1.2.3.4",
	}
	for in, want := range cases {
		if got := NormalizeIP(in); got != want {
			t.Errorf("NormalizeIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCursorRoundTrip(t *testing.T) {
	c := Cursor{At: time.UnixMicro(1700000000123456).UTC(), ID: uuid.New()}
	got, err := ParseCursor(c.Encode())
	if err != nil || got.ID != c.ID || !got.At.Equal(c.At) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for _, bad := range []string{"!!", "YQ", Cursor{}.Encode()[:5]} {
		if _, err := ParseCursor(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if c, err := ParseCursor(""); c != nil || err != nil {
		t.Fatal("empty cursor must be nil")
	}
}

func TestActionValidation(t *testing.T) {
	for _, a := range Actions {
		if !ValidAction(a) {
			t.Errorf("%s invalid", a)
		}
	}
	for _, a := range []string{"", "git", "Git.Push", "a.b c", strings.Repeat("a.", 30)} {
		if ValidAction(a) {
			t.Errorf("%q accepted", a)
		}
	}
}

type memStore struct{ rows []Entry }

func (m *memStore) Append(_ context.Context, e Entry) error { m.rows = append(m.rows, e); return nil }
func (m *memStore) ProjectID(context.Context, uuid.UUID, string) (uuid.UUID, bool, error) {
	return uuid.Nil, false, nil
}
func (m *memStore) List(_ context.Context, org uuid.UUID, _ Filter, after *Cursor, limit int) ([]Entry, error) {
	var out []Entry
	for _, e := range m.rows { // rows are kept newest first
		if after != nil && !(e.CreatedAt.Before(after.At) || (e.CreatedAt.Equal(after.At) && e.ID.String() < after.ID.String())) {
			continue
		}
		out = append(out, e)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func TestRecorderRules(t *testing.T) {
	st := &memStore{}
	r := NewRecorder(st)
	org := uuid.New()
	if err := r.Record(context.Background(), Input{OrgID: org, Action: ActTeamDrift, ResourceType: ResProject, ActorLabel: "system", IP: "1.2.3.4:99"}); err != nil {
		t.Fatal(err)
	}
	e := st.rows[0]
	if e.UserID != nil || e.IP != "1.2.3.4" || e.ActorLabel != "system" || e.Metadata == nil {
		t.Fatalf("entry: %+v", e)
	}
	bad := []Input{
		{Action: ActTeamDrift, ResourceType: ResProject},
		{OrgID: org, Action: "nope", ResourceType: ResProject},
		{OrgID: org, Action: ActTeamDrift, ResourceType: "Bad Type"},
		{OrgID: org, Action: ActTeamDrift, ResourceType: ResProject, New: map[string]any{"api_token": "x"}},
		{OrgID: org, Action: ActTeamDrift, ResourceType: ResProject, Meta: map[string]any{"big": strings.Repeat("x", maxValuesBytes+1)}},
	}
	for i, in := range bad {
		if err := r.Record(context.Background(), in); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestExportCSVNeutralizesAndTruncates(t *testing.T) {
	st := &memStore{}
	org := uuid.New()
	base := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 25; i++ {
		st.rows = append(st.rows, Entry{ID: uuid.New(), OrgID: org, Action: "git.push", ResourceType: "project",
			ActorName: "=cmd|' /C calc'!A0", CreatedAt: base.Add(-time.Duration(i) * time.Second)})
	}
	s := NewService(st)
	var buf bytes.Buffer
	res, err := s.Export(context.Background(), org, Filter{}, "", 10, &buf)
	if err != nil || res.Rows != 10 || !res.Truncated || res.Next == "" {
		t.Fatalf("export: %+v %v", res, err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(recs) != 11 {
		t.Fatalf("records %d %v", len(recs), err)
	}
	if !reflect.DeepEqual(recs[0], CSVHeader) {
		t.Fatal("header")
	}
	for _, rec := range recs[1:] {
		if !strings.HasPrefix(rec[4], "'=") {
			t.Fatalf("actor name not neutralized: %q", rec[4])
		}
	}
	// continuing from Next yields the remaining 15 without overlap
	var buf2 bytes.Buffer
	res2, err := s.Export(context.Background(), org, Filter{}, res.Next, 0, &buf2)
	if err != nil || res2.Rows != 15 || res2.Truncated {
		t.Fatalf("continue: %+v %v", res2, err)
	}
}

func TestListPagesAreStable(t *testing.T) {
	st := &memStore{}
	org := uuid.New()
	base := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 7; i++ { // identical timestamps stress the id tie-break
		st.rows = append(st.rows, Entry{ID: uuid.New(), OrgID: org, CreatedAt: base})
	}
	// order newest first, ties by id descending
	for i := range st.rows {
		for j := i + 1; j < len(st.rows); j++ {
			if st.rows[j].ID.String() > st.rows[i].ID.String() {
				st.rows[i], st.rows[j] = st.rows[j], st.rows[i]
			}
		}
	}
	s := NewService(st)
	seen := map[uuid.UUID]bool{}
	cur := ""
	for {
		page, next, err := s.List(context.Background(), org, Filter{}, cur, 3)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page {
			if seen[e.ID] {
				t.Fatal("duplicate row across pages")
			}
			seen[e.ID] = true
		}
		if next == "" {
			break
		}
		cur = next
	}
	if len(seen) != 7 {
		t.Fatalf("saw %d rows", len(seen))
	}
}

func TestFilterValidation(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-time.Hour)
	if (Filter{Action: "git.*"}).Validate() != nil || (Filter{Action: "git.push"}).Validate() != nil {
		t.Fatal("valid filters rejected")
	}
	for _, f := range []Filter{{Action: "GIT"}, {Action: "a;drop"}, {Since: &now, Until: &earlier}} {
		if f.Validate() == nil {
			t.Errorf("%+v accepted", f)
		}
	}
}

// Immutability: neither the write nor the read surface can edit or delete a row.
func TestNoUpdateOrDeleteSurface(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf((*Writer)(nil)).Elem(), reflect.TypeOf((*Reader)(nil)).Elem(), reflect.TypeOf(&Service{}), reflect.TypeOf(&Recorder{})} {
		for i := 0; i < typ.NumMethod(); i++ {
			n := strings.ToLower(typ.Method(i).Name)
			for _, bad := range []string{"delete", "update", "remove", "edit", "purge", "set"} {
				if strings.Contains(n, bad) && n != "setshared" {
					t.Errorf("%s exposes %s", typ, typ.Method(i).Name)
				}
			}
		}
	}
}

func TestRetentionNeverBelowMinimum(t *testing.T) {
	if (Config{RetentionDays: 30}).Normalized().RetentionDays != MinRetentionDays {
		t.Fatal("retention below minimum")
	}
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	r := &Retention{Cfg: Config{RetentionDays: 1}, Now: func() time.Time { return now }}
	if want := now.Add(-400 * 24 * time.Hour); !r.Cutoff().Equal(want) {
		t.Fatalf("cutoff %v", r.Cutoff())
	}
}
