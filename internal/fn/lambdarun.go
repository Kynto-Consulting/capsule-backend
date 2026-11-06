package fn

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/vpn"
)

// Functions with runtime "lambda" are executed by the backend, not by a work node: the backend invokes the function's own
// Lambda in resumable batches (LambdaExecutor.Run), mints a new run token for every batch and hands it in the Invoke
// payload (never in the Lambda's environment variables). When the function uses a tunnel, the node that owns it keeps the
// tunnel up and attaches it to the relay (Sync -> RelayTunnels); the Lambda reaches it through the relay with its token.

var errRunStopped = errors.New("fn: run is no longer running")

// RedactEnv teaches the redactor every secret an environment carries: the run token, database URLs (and their passwords)
// and the keys of the buckets granted by storage scopes.
func RedactEnv(red *vpn.Redactor, env map[string]string) {
	red.Add(env["CAPSULE_TOKEN"])
	for k, v := range env {
		switch {
		case strings.HasPrefix(k, "CAPSULE_DB_"):
			red.Add(v)
			if u, err := url.Parse(v); err == nil && u.User != nil {
				if pw, ok := u.User.Password(); ok {
					red.Add(pw)
				}
			}
		case strings.HasPrefix(k, "CAPSULE_STORAGE_") && (strings.HasSuffix(k, "SECRET_ACCESS_KEY") || strings.HasSuffix(k, "ACCESS_KEY_ID")):
			red.Add(v)
		}
	}
}

func (s *Service) liveWindow() time.Duration {
	if s.LiveWindow > 0 {
		return s.LiveWindow
	}
	return 2 * time.Minute
}

func (s *Service) tunnelAssignment(t *vpn.Tunnel) (*TunnelAssignment, error) {
	sec, err := s.VPN.Secret(t)
	if err != nil {
		return nil, err
	}
	return &TunnelAssignment{ID: t.ID, Provider: t.Provider, Host: t.Host, CIDRs: t.CIDRs, CertPin: t.CertPin,
		MaxConns: t.MaxConns, BandwidthBps: t.BandwidthBps, Version: t.UpdatedAt.UnixNano(), Secret: sec}, nil
}

// RelayTunnels returns the tunnels `node` must keep attached to the relay: those of the running Lambda runs assigned to it.
// This is, like Claim, a place where tunnel credentials leave the backend, only towards the authenticated node that owns the run.
func (s *Service) RelayTunnels(ctx context.Context, node string) ([]TunnelAssignment, error) {
	running, err := s.Store.RunningRuns(ctx)
	if err != nil {
		return nil, err
	}
	var out []TunnelAssignment
	seen := map[uuid.UUID]bool{}
	for _, r := range running {
		if r.NodeID != node {
			continue
		}
		f, err := s.Store.GetFunctionByID(ctx, r.FunctionID)
		if err != nil || f.Runtime != RuntimeLambda || f.VPNID == nil || seen[*f.VPNID] {
			continue
		}
		t, err := s.VPN.Store.GetByID(ctx, *f.VPNID)
		if err != nil || !t.Enabled || t.ProjectID != f.ProjectID {
			continue
		}
		ta, err := s.tunnelAssignment(t)
		if err != nil {
			continue
		}
		seen[t.ID] = true
		out = append(out, *ta)
	}
	return out, nil
}

// NodeServesTunnel reports whether `node` may attach to the relay for the tunnel (it owns a running Lambda run that uses it).
func (s *Service) NodeServesTunnel(ctx context.Context, node string, tunnel uuid.UUID) bool {
	list, err := s.RelayTunnels(ctx, node)
	if err != nil {
		return false
	}
	for _, ta := range list {
		if ta.ID == tunnel {
			return true
		}
	}
	return false
}

// RelayTarget resolves a run token to the tunnel its function uses and the networks declared for it. ok is false when the
// token is not live, the function has no tunnel or the tunnel is off (kill switch).
func (s *Service) RelayTarget(ctx context.Context, token string) (claims Claims, t *vpn.Tunnel, ok bool) {
	claims = s.Introspect(ctx, token)
	if !claims.Active {
		return claims, nil, false
	}
	r, err := s.Store.GetRun(ctx, claims.RunID)
	if err != nil {
		return claims, nil, false
	}
	f, err := s.Store.GetFunctionByID(ctx, r.FunctionID)
	if err != nil || f.VPNID == nil || !f.Enabled {
		return claims, nil, false
	}
	t, err = s.VPN.Store.GetByID(ctx, *f.VPNID)
	if err != nil || !t.Enabled || t.ProjectID != f.ProjectID {
		return claims, nil, false
	}
	return claims, t, true
}

func (s *Service) stopLambda(id uuid.UUID) {
	s.lmu.Lock()
	c := s.lcancel[id]
	delete(s.lcancel, id)
	s.lmu.Unlock()
	if c != nil {
		c()
	}
	if s.Relay != nil {
		s.Relay.CloseRun(id.String())
	}
}

// DispatchLambda starts the queued runs of Lambda functions. A run of a function with a tunnel starts only when a work node
// is alive to own the tunnel (otherwise it waits in the queue). Safe to call every few seconds from several instances:
// TryStart is atomic and also enforces max_concurrency.
func (s *Service) DispatchLambda(ctx context.Context) error {
	if s.Lambda == nil {
		return nil
	}
	queued, err := s.Store.QueuedRuns(ctx, 50)
	if err != nil {
		return err
	}
	for _, r := range queued {
		f, err := s.Store.GetFunctionByID(ctx, r.FunctionID)
		if err != nil || !f.Enabled || f.Runtime != RuntimeLambda || f.Image == "" {
			continue
		}
		node := "lambda"
		var t *vpn.Tunnel
		if f.VPNID != nil {
			if t, err = s.VPN.Store.GetByID(ctx, *f.VPNID); err != nil || !t.Enabled || t.ProjectID != f.ProjectID {
				continue
			}
			if node, err = s.Store.LiveNode(ctx, s.now().Add(-s.liveWindow())); err != nil {
				continue // no work node alive: nobody could own the tunnel
			}
		}
		ok, err := s.Store.TryStart(ctx, r.ID, node, s.now())
		if err != nil || !ok {
			continue
		}
		run, err := s.Store.GetRun(ctx, r.ID)
		if err != nil {
			continue
		}
		if t != nil {
			s.VPN.Audit(ctx, t, vpn.EventRunStarted, fmt.Sprintf("function %s run %s started on lambda (%s by %s); scopes %s", f.Name, run.ID, run.Trigger, run.TriggeredBy, strings.Join(run.Scopes, ",")), "node:"+node)
		}
		go s.executeLambda(ctx, f, run)
	}
	return nil
}

func (s *Service) executeLambda(ctx context.Context, f *Function, run *Run) {
	rctx, cancel := context.WithCancel(ctx)
	s.lmu.Lock()
	if s.lcancel == nil {
		s.lcancel = map[uuid.UUID]context.CancelFunc{}
	}
	s.lcancel[run.ID] = cancel
	s.lmu.Unlock()
	defer func() {
		s.lmu.Lock()
		delete(s.lcancel, run.ID)
		s.lmu.Unlock()
		cancel()
	}()

	red := vpn.NewRedactor()
	fail := func(status, msg string) {
		var in, out int64
		if s.Relay != nil {
			in, out = s.Relay.Bytes(run.ID.String())
		}
		s.finishLambda(run, status, in, out, red.Mask(msg))
	}

	if err := s.Lambda.Ensure(rctx, f, f.Image); err != nil {
		fail(RunFailed, "could not prepare the lambda: "+err.Error())
		return
	}
	if f.VPNID != nil {
		wait := s.RelayWait
		if wait <= 0 {
			wait = 90 * time.Second
		}
		if !s.waitRelay(rctx, f.VPNID.String(), wait) {
			if rctx.Err() == nil {
				fail(RunFailed, fmt.Sprintf("the tunnel's work node did not attach to the relay within %s", wait))
			}
			return
		}
	}

	mint := func(attempt int) (map[string]string, error) {
		cur, err := s.Store.GetRun(rctx, run.ID)
		if err != nil || cur.Status != RunRunning {
			return nil, errRunStopped
		}
		if f.VPNID != nil {
			if t, err := s.VPN.Store.GetByID(rctx, *f.VPNID); err != nil || !t.Enabled {
				return nil, errRunStopped
			}
		}
		now := s.now()
		_ = s.Store.RevokeRunTokens(rctx, run.ID, now) // the previous batch's token dies here
		plain, hash := NewToken(TokenPrefix)
		if err := s.Store.PutToken(rctx, RunToken{Hash: hash, RunID: run.ID, ProjectID: run.ProjectID, Scopes: run.Scopes, ExpiresAt: now.Add(MaxInvoke + TokenGrace)}); err != nil {
			return nil, err
		}
		env := s.runEnv(rctx, f, run, plain, true) // a Lambda is outside the host: buckets by their public endpoint
		delete(env, "CAPSULE_PAYLOAD") // the payload travels in the invoke payload itself
		if f.VPNID != nil {
			env["CAPSULE_VPN_RELAY"] = strings.TrimRight(s.APIBase, "/") + "/api/v1/fn/relay/connect"
		}
		RedactEnv(red, env)
		return env, nil
	}

	deadline := run.StartedAt
	d := s.now().Add(time.Duration(f.TimeoutSeconds) * time.Second)
	if deadline != nil {
		d = deadline.Add(time.Duration(f.TimeoutSeconds) * time.Second)
	}
	o, err := s.Lambda.Run(rctx, f, run, d, mint)
	if errors.Is(err, errRunStopped) || rctx.Err() != nil {
		return // cancelled or killed: finish() already recorded it
	}
	in, out := o.BytesIn, o.BytesOut
	if s.Relay != nil {
		if ri, ro := s.Relay.Bytes(run.ID.String()); ri+ro > 0 {
			in, out = ri, ro // what really crossed the tunnel, counted by the relay, not what the function says
		}
	}
	switch {
	case err != nil:
		s.finishLambda(run, RunFailed, in, out, red.Mask(o.Log+err.Error()))
	default:
		s.finishLambda(run, o.Status, in, out, red.Mask(o.Log))
	}
}

func (s *Service) finishLambda(run *Run, status string, in, out int64, tail string) {
	if len(tail) > 16<<10 {
		tail = tail[len(tail)-16<<10:]
	}
	_ = s.Finish(context.Background(), run.ID, status, nil, in, out, tail)
	if s.Relay != nil {
		s.Relay.Forget(run.ID.String())
	}
}

func (s *Service) waitRelay(ctx context.Context, tunnel string, wait time.Duration) bool {
	if s.Relay == nil {
		return false
	}
	deadline := time.Now().Add(wait)
	for {
		if s.Relay.Idle(tunnel) > 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// Delete removes a function: queued and running runs are cancelled and, for the lambda runtime, so is the AWS Lambda.
func (s *Service) Delete(ctx context.Context, f *Function) error {
	for _, list := range []func(context.Context) ([]*Run, error){s.Store.RunningRuns, func(c context.Context) ([]*Run, error) { return s.Store.QueuedRuns(c, 1000) }} {
		runs, err := list(ctx)
		if err != nil {
			return err
		}
		for _, r := range runs {
			if r.FunctionID == f.ID {
				_ = s.Cancel(ctx, r)
			}
		}
	}
	if f.Runtime == RuntimeLambda && s.Lambda != nil {
		if err := s.Lambda.Remove(ctx, f); err != nil {
			return fmt.Errorf("could not delete the lambda: %w", err)
		}
	}
	if s.Registry != nil { // the images Capsule built for it (capsule/fn-<id>); a repository that does not exist is not an error
		if err := s.Registry.RemoveFunctionImages(ctx, f); err != nil {
			return fmt.Errorf("could not delete the function's image repository: %w", err)
		}
	}
	return s.Store.DeleteFunction(ctx, f.ID)
}
