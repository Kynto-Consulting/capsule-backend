package environments

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestWindowOpenTable(t *testing.T) {
	lima := Window{Days: []string{"mon", "tue", "wed", "thu", "fri"}, From: "09:00", To: "18:00", TZ: "America/Lima"}
	night := Window{Days: []string{"fri"}, From: "22:00", To: "02:00", TZ: "UTC"} // crosses midnight into Saturday
	ny := Window{Days: []string{}, From: "01:00", To: "04:00", TZ: "America/New_York"}
	cases := []struct {
		name string
		w    Window
		at   time.Time
		open bool
	}{
		{"lima open", lima, time.Date(2026, 11, 4, 14, 0, 0, 0, time.UTC), true},           // Wed 09:00 Lima
		{"lima before", lima, time.Date(2026, 11, 4, 13, 59, 0, 0, time.UTC), false},       // 08:59
		{"lima end exclusive", lima, time.Date(2026, 11, 4, 23, 0, 0, 0, time.UTC), false}, // 18:00
		{"lima saturday", lima, time.Date(2026, 11, 7, 17, 0, 0, 0, time.UTC), false},
		{"cross midnight same day", night, time.Date(2026, 11, 6, 23, 0, 0, 0, time.UTC), true},
		{"cross midnight next day", night, time.Date(2026, 11, 7, 1, 0, 0, 0, time.UTC), true},
		{"cross midnight over", night, time.Date(2026, 11, 7, 2, 0, 0, 0, time.UTC), false},
		// New York leaves DST on 2026-11-01 (02:00 EDT -> 01:00 EST): 01:00-04:00 local is evaluated in local time
		{"ny after fall back", ny, time.Date(2026, 11, 1, 7, 30, 0, 0, time.UTC), true},   // 02:30 EST
		{"ny before fall back", ny, time.Date(2026, 10, 31, 6, 30, 0, 0, time.UTC), true}, // 02:30 EDT
		{"ny 05:00 local closed", ny, time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC), false},
	}
	for _, c := range cases {
		if got, _ := WindowOpen([]Window{c.w}, c.at); got != c.open {
			t.Errorf("%s: open=%v want %v", c.name, got, c.open)
		}
	}
	if open, _ := WindowOpen(nil, time.Now()); !open {
		t.Error("no windows must be always open")
	}
}

func TestOpenAtOrAfterAcrossDST(t *testing.T) {
	// New York springs forward on 2026-03-08. Window 09:00-17:00 local on every day.
	w := []Window{{Days: []string{}, From: "09:00", To: "17:00", TZ: "America/New_York"}}
	// 2026-03-07 23:00 UTC is Saturday 18:00 EST: closed; next opening is Sunday 09:00 EDT = 13:00 UTC
	got := OpenAtOrAfter(w, time.Date(2026, 3, 7, 23, 0, 0, 0, time.UTC))
	if want := time.Date(2026, 3, 8, 13, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("got %s want %s", got, want)
	}
	// the day before DST the same window opens at 14:00 UTC
	got = OpenAtOrAfter(w, time.Date(2026, 3, 6, 23, 0, 0, 0, time.UTC))
	if want := time.Date(2026, 3, 7, 14, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestValidateWindow(t *testing.T) {
	bad := []Window{
		{From: "09:00", To: "09:00", TZ: "UTC"}, {From: "9:00", To: "10:00", TZ: "UTC"},
		{From: "09:00", To: "10:00", TZ: "Nowhere/City"}, {From: "09:00", To: "10:00", TZ: ""},
		{Days: []string{"funday"}, From: "09:00", To: "10:00", TZ: "UTC"}, {From: "25:00", To: "10:00", TZ: "UTC"},
	}
	for i, w := range bad {
		if ValidateWindow(w) == "" {
			t.Errorf("case %d should be invalid", i)
		}
	}
	if m := ValidateWindow(Window{Days: []string{"MON"}, From: "09:00", To: "18:00", TZ: "America/Lima"}); m != "" {
		t.Errorf("valid window refused: %s", m)
	}
}

func TestAdvanceStateTable(t *testing.T) {
	now := time.Date(2026, 11, 4, 15, 0, 0, 0, time.UTC)
	req := uuid.New()
	other := uuid.New()
	approved := func(by uuid.UUID, self bool) Approval {
		return Approval{UserID: &by, Decision: "approved", SelfApproval: self}
	}
	env := Environment{RequiredApprovals: 1}
	cases := []struct {
		name    string
		env     Environment
		p       Promotion
		want    string
		changed bool
	}{
		{"pending without approvals stays", env, Promotion{Status: StatusPending}, StatusPending, false},
		{"pending with approval goes approved", env, Promotion{Status: StatusPending, Approvals: []Approval{approved(other, false)}}, StatusApproved, true},
		{"requester approval ignored without opt-in", env, Promotion{Status: StatusPending, Approvals: []Approval{approved(req, true)}}, StatusPending, false},
		{"requester approval counts with opt-in", Environment{RequiredApprovals: 1, AllowSelfApproval: true}, Promotion{Status: StatusPending, Approvals: []Approval{approved(req, true)}}, StatusApproved, true},
		{"two required, one given", Environment{RequiredApprovals: 2}, Promotion{Status: StatusPending, Approvals: []Approval{approved(other, false)}}, StatusPending, false},
		{"wait pending goes waiting", Environment{RequiredApprovals: 1, WaitMinutes: 5}, Promotion{Status: StatusPending, Approvals: []Approval{approved(other, false)}}, StatusWaiting, true},
		{"waiting elapsed goes approved", Environment{WaitMinutes: 5}, Promotion{Status: StatusWaiting, QuorumAt: ptr(now.Add(-6 * time.Minute)), NotBefore: ptr(now.Add(-time.Minute))}, StatusApproved, true},
		{"waiting not yet stays", Environment{WaitMinutes: 5}, Promotion{Status: StatusWaiting, QuorumAt: ptr(now.Add(-time.Minute)), NotBefore: ptr(now.Add(4 * time.Minute))}, StatusWaiting, false},
		{"approved stays approved", Environment{}, Promotion{Status: StatusApproved, QuorumAt: ptr(now)}, StatusApproved, false},
		{"deploying untouched", env, Promotion{Status: StatusDeploying}, StatusDeploying, false},
	}
	for _, c := range cases {
		got, _, _, changed := Advance(c.env, c.p, now)
		if got != c.want || changed != c.changed {
			t.Errorf("%s: got %s changed=%v, want %s changed=%v", c.name, got, changed, c.want, c.changed)
		}
	}
}

func ptr(t time.Time) *time.Time { return &t }

func TestIsApproverUsesTheListNotTheRole(t *testing.T) {
	u := uuid.New()
	env := Environment{Reviewers: []Reviewer{{Type: "user", UserID: &u}, {Type: "role", Role: "deployer"}}}
	if !IsApprover(env, u, "viewer") {
		t.Error("listed user must be an approver whatever the role")
	}
	if !IsApprover(env, uuid.New(), "deployer") {
		t.Error("listed role must match")
	}
	if IsApprover(env, uuid.New(), "admin") {
		t.Error("admin not listed must not be an approver")
	}
	if IsApprover(Environment{}, u, "admin") {
		t.Error("empty list approves nobody")
	}
}

func TestNormalizeDefaults(t *testing.T) {
	self := uuid.New()
	e, err := Normalize(Input{Name: "production", Kind: "production"}, self)
	if err != nil || e.RequiredApprovals != 1 || e.AllowSelfApproval || e.TargetProjectID != self || !e.RequireSecurityPolicy {
		t.Fatalf("%+v %v", e, err)
	}
	e, err = Normalize(Input{Name: "qa", Kind: "other"}, self)
	if err != nil || e.RequiredApprovals != 0 || e.RequireChecksOnSHA || len(e.Reviewers) != 0 {
		t.Fatalf("%+v %v", e, err)
	}
	if _, err := Normalize(Input{Name: "qa", Kind: "other", BranchPatterns: []string{""}}, self); err == nil {
		t.Error("empty glob must be refused")
	}
	two := 2
	u := uuid.New()
	if _, err := Normalize(Input{Name: "qa", Kind: "other", RequiredApprovals: &two, Reviewers: []Reviewer{{Type: "user", UserID: &u}}}, self); err == nil {
		t.Error("N approvals with N listed users and no self approval can never be met")
	}
}
