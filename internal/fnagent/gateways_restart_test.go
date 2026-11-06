package fnagent

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/vpn"
)

type estadoTunnel struct {
	status string
	closed bool
}

func (t *estadoTunnel) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not used")
}
func (t *estadoTunnel) Health() (string, time.Time, string) { return t.status, time.Time{}, "" }
func (t *estadoTunnel) Close()                              { t.closed = true }

// A tunnel whose process died (FortiGate idle timeout) reports error: Ensure must open a new one, not hand out the dead gateway.
func TestEnsureRestartsADeadTunnel(t *testing.T) {
	var opened []*estadoTunnel
	m := NewManager()
	m.Open = func(fn.TunnelAssignment, *vpn.Redactor) (Tunnel, error) {
		x := &estadoTunnel{status: vpn.StatusUp}
		opened = append(opened, x)
		return x, nil
	}
	ta := fn.TunnelAssignment{ID: uuid.New(), Provider: "fortigate", Version: 1, CIDRs: []string{"10.48.0.10/32"}}
	g1, err := m.Ensure(ta)
	if err != nil {
		t.Fatal(err)
	}
	if g2, _ := m.Ensure(ta); g2 != g1 || len(opened) != 1 {
		t.Fatalf("a healthy tunnel must be reused (opened %d)", len(opened))
	}
	opened[0].status = vpn.StatusError
	g3, err := m.Ensure(ta)
	if err != nil {
		t.Fatal(err)
	}
	if g3 == g1 || len(opened) != 2 || !opened[0].closed {
		t.Fatalf("a dead tunnel must be closed and reopened (opened %d, closed %v)", len(opened), opened[0].closed)
	}
}
