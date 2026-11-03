package handlers

import (
	"context"
	"fmt"

	"github.com/kynto/capsule/backend/internal/domain"
)

// healthPatch carries the optional health fields of PATCH /orgs/{o}/projects/{p}.
type healthPatch struct {
	Path     *string
	Timeout  *int
	Interval *int
	Expected *string
}

func (p healthPatch) empty() bool {
	return p.Path == nil && p.Timeout == nil && p.Interval == nil && p.Expected == nil
}

// mergeHealth applies a patch on top of the current settings and validates the result.
func mergeHealth(cur domain.ProjectHealthConfig, p healthPatch) (domain.ProjectHealthConfig, error) {
	out := cur
	if p.Path != nil {
		if err := domain.ValidateHealthPath(*p.Path); err != nil {
			return cur, err
		}
		out.Path = *p.Path
	}
	if p.Timeout != nil {
		if err := domain.ValidateHealthTimeout(*p.Timeout); err != nil {
			return cur, err
		}
		out.TimeoutSeconds = *p.Timeout
	}
	if p.Interval != nil {
		if err := domain.ValidateHealthInterval(*p.Interval); err != nil {
			return cur, err
		}
		out.IntervalSeconds = *p.Interval
	}
	if p.Expected != nil {
		if err := domain.ValidateExpectedStatus(*p.Expected); err != nil {
			return cur, err
		}
		out.ExpectedStatus = *p.Expected
	}
	if out.IntervalSeconds > out.TimeoutSeconds {
		return cur, fmt.Errorf("health_interval_seconds cannot exceed health_timeout_seconds")
	}
	return out, nil
}

// SetHealthStore wires persistence of the per-project health settings.
func (h *ProjectHandler) SetHealthStore(s domain.ProjectHealthStore) { h.health = s }

// attachHealth fills the health_* fields of a project response (defaults when
// the store is not wired or fails: the project itself must still be served).
func (h *ProjectHandler) attachHealth(ctx context.Context, p *domain.Project) {
	if p == nil {
		return
	}
	c := domain.DefaultProjectHealthConfig()
	if h.health != nil {
		if got, err := h.health.GetHealthConfig(ctx, p.ID); err == nil {
			c = got
		}
	}
	p.HealthPath = &c.Path
	p.HealthTimeoutSeconds = &c.TimeoutSeconds
	p.HealthIntervalSeconds = &c.IntervalSeconds
	p.HealthExpectedStatus = &c.ExpectedStatus
}
