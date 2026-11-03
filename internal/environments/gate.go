package environments

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CountApprovals counts the approvals that count toward quorum: the requester's own approval
// only counts when the environment explicitly allows self-approval.
func CountApprovals(env Environment, p Promotion) int {
	n := 0
	for _, a := range p.Approvals {
		if a.Decision != "approved" {
			continue
		}
		if a.SelfApproval && !env.AllowSelfApproval {
			continue
		}
		n++
	}
	return n
}

// NextAfterQuorum decides where a promotion whose approvals were satisfied at quorumAt goes at
// instant now: approved (ready for the queue) or waiting until notBefore (wait time or window).
func NextAfterQuorum(env Environment, quorumAt, now time.Time) (status string, notBefore *time.Time) {
	t := quorumAt.Add(time.Duration(env.WaitMinutes) * time.Minute)
	if t.After(now) {
		nb := OpenAtOrAfter(env.Windows, t)
		return StatusWaiting, &nb
	}
	if open, _ := WindowOpen(env.Windows, now); open {
		return StatusApproved, nil
	}
	nb := OpenAtOrAfter(env.Windows, now)
	return StatusWaiting, &nb
}

// Advance returns the state a non-final promotion should be in at now. changed is false when it
// stays as it is. It is pure: the clock and the approvals are inputs.
func Advance(env Environment, p Promotion, now time.Time) (status string, notBefore, quorumAt *time.Time, changed bool) {
	switch p.Status {
	case StatusPending:
		if CountApprovals(env, p) < env.RequiredApprovals {
			return p.Status, p.NotBefore, p.QuorumAt, false
		}
		q := now
		st, nb := NextAfterQuorum(env, q, now)
		return st, nb, &q, true
	case StatusWaiting, StatusApproved:
		q := now
		if p.QuorumAt != nil {
			q = *p.QuorumAt
		}
		st, nb := NextAfterQuorum(env, q, now)
		same := st == p.Status && ((nb == nil && p.NotBefore == nil) || (nb != nil && p.NotBefore != nil && nb.Equal(*p.NotBefore)))
		return st, nb, &q, !same
	}
	return p.Status, p.NotBefore, p.QuorumAt, false
}

// IsApprover reports whether user (with role) is on the environment's approver list. The list
// decides, never the role alone: an admin who is not listed cannot approve.
func IsApprover(env Environment, user uuid.UUID, role string) bool {
	for _, r := range env.Reviewers {
		switch r.Type {
		case "user":
			if r.UserID != nil && *r.UserID == user {
				return true
			}
		case "role":
			if role != "" && r.Role == role {
				return true
			}
		}
	}
	return false
}

// DynamicConditions renders the live gates (approvals, wait, window) of a promotion.
func DynamicConditions(env Environment, p Promotion, now time.Time) []Condition {
	got := CountApprovals(env, p)
	out := []Condition{{Name: "approvals", OK: got >= p.RequiredApprovals,
		Detail: fmt.Sprintf("%d of %d approvals", got, p.RequiredApprovals)}}
	if env.WaitMinutes > 0 {
		ok := p.QuorumAt != nil && !p.QuorumAt.Add(time.Duration(env.WaitMinutes)*time.Minute).After(now)
		out = append(out, Condition{Name: "wait", OK: ok, Detail: fmt.Sprintf("%d minutes after the last approval", env.WaitMinutes)})
	}
	if len(env.Windows) > 0 {
		open, _ := WindowOpen(env.Windows, now)
		d := "inside the deployment window"
		if !open {
			d = "outside the deployment window"
			if p.NotBefore != nil {
				d += ", next opening " + p.NotBefore.UTC().Format(time.RFC3339)
			}
		}
		out = append(out, Condition{Name: "window", OK: open, Detail: d})
	}
	return out
}
