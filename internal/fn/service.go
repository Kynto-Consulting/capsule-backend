package fn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/vpn"
)

// Errors.
var (
	ErrNotFound = errors.New("fn: not found")
	ErrConflict = errors.New("fn: already exists")
	ErrDisabled = errors.New("fn: function or tunnel disabled")
)

// Store persists functions, runs and run tokens.
type Store interface {
	CreateFunction(ctx context.Context, f *Function) error
	GetFunction(ctx context.Context, projectID uuid.UUID, name string) (*Function, error)
	GetFunctionByID(ctx context.Context, id uuid.UUID) (*Function, error)
	ListFunctions(ctx context.Context, projectID uuid.UUID) ([]*Function, error)
	CronFunctions(ctx context.Context) ([]*Function, error)
	DeleteFunction(ctx context.Context, id uuid.UUID) error
	// CASLastCron sets last_cron_at = now only if it still equals old (several backend instances never double-fire).
	CASLastCron(ctx context.Context, id uuid.UUID, old *time.Time, now time.Time) (bool, error)

	EnqueueRun(ctx context.Context, r *Run) error
	QueuedRuns(ctx context.Context, limit int) ([]*Run, error)
	RunningRuns(ctx context.Context) ([]*Run, error)
	// TryStart moves a queued run to running when the function has fewer than max_concurrency running runs.
	TryStart(ctx context.Context, runID uuid.UUID, node string, now time.Time) (bool, error)
	FinishRun(ctx context.Context, id uuid.UUID, status string, exit *int, in, out int64, tail string, now time.Time) error
	GetRun(ctx context.Context, id uuid.UUID) (*Run, error)
	ListRuns(ctx context.Context, functionID uuid.UUID, limit int) ([]*Run, error)

	PutToken(ctx context.Context, t RunToken) error
	GetToken(ctx context.Context, hash string) (*RunToken, error)
	RevokeRunTokens(ctx context.Context, runID uuid.UUID, now time.Time) error

	NodeByHash(ctx context.Context, hash string) (string, error)
	// LiveNode is the node that reported most recently since the given time (ErrNotFound when none did).
	LiveNode(ctx context.Context, since time.Time) (string, error)
}

// Service is the planner/claim logic.
type Service struct {
	Store   Store
	VPN     *vpn.Service
	Now     func() time.Time
	APIBase string // public base URL of the Capsule API, handed to the function as CAPSULE_API
	// DBs resolves a `db:<name>` scope to a connection URL on the internal route (host.docker.internal:<port>). Optional.
	DBs DBResolver
	// Storage resolves a `storage:<name>` scope to the S3 access of that bucket (endpoint, public_endpoint, bucket, access_key_id,
	// secret_access_key, region). "endpoint" is the internal route (containers on the work node); "public_endpoint" is the project's
	// https://<slug>-storage host, used by Lambda runs. Nil until the object store is wired (the SDK then reports the scope as unavailable).
	Storage StorageResolver

	// Lambda runs functions deployed with --runtime lambda as their own AWS Lambda, in resumable batches. Nil disables the runtime
	// (Deploy rejects it): it is switched on explicitly because the first run of a function creates AWS resources.
	Lambda *LambdaExecutor
	// Relay is the API-side rendezvous that lets a Lambda reach the tunnel without NAT (see gateway.Relay). Nil: Lambda
	// functions cannot use a tunnel.
	Relay RelayHub
	// RelayWait is how long a Lambda run waits for its tunnel's node to attach before the first batch (default 90 s).
	RelayWait time.Duration
	// LiveWindow is how recently a node must have reported to be given a Lambda run's tunnel (default 2 min).
	LiveWindow time.Duration

	lmu     sync.Mutex
	lcancel map[uuid.UUID]context.CancelFunc
}

// RelayHub is what the service needs from the relay (implemented by *gateway.Relay).
type RelayHub interface {
	Idle(tunnel string) int
	Bytes(run string) (in, out int64)
	CloseRun(run string)
	Forget(run string)
	DropTunnel(tunnel string)
}

// StorageResolver returns the S3 access of the project's bucket `name`.
type StorageResolver func(ctx context.Context, projectID uuid.UUID, name string) (map[string]string, error)

// DBResolver returns the URL of the project's database `name`.
type DBResolver func(ctx context.Context, projectID uuid.UUID, name string) (string, error)

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Deploy creates or replaces nothing: a function name is unique per project (redeploy = delete + deploy, runs are kept by id).
func (s *Service) Deploy(ctx context.Context, orgID, projectID uuid.UUID, by *uuid.UUID, spec Spec) (*Function, error) {
	spec, err := spec.Normalize()
	if err != nil {
		return nil, err
	}
	if spec.Runtime == RuntimeLambda && s.Lambda == nil {
		return nil, invalid("the lambda runtime is not enabled on this Capsule; use --runtime container")
	}
	if spec.Runtime == RuntimeLambda && spec.VPN != "" && s.Relay == nil {
		return nil, invalid("the lambda runtime cannot reach tunnels on this Capsule (no relay); use --runtime container")
	}
	var vpnID *uuid.UUID
	if spec.VPN != "" {
		t, err := s.VPN.Store.GetByName(ctx, projectID, spec.VPN)
		if err != nil { // lookup is by project: a tunnel of another project is simply not found
			return nil, invalid("tunnel %q does not exist in this project", spec.VPN)
		}
		vpnID = &t.ID
	}
	mem, _ := ParseMemoryMB(spec.Memory)
	to, _ := ParseTimeout(spec.Timeout)
	f := &Function{
		ID: uuid.New(), OrgID: orgID, ProjectID: projectID, Name: spec.Name, Image: spec.Image, Entry: spec.Entry, Runtime: spec.Runtime, VPNID: vpnID,
		Cron: spec.Cron, MemoryMB: mem, CPUs: spec.CPUs, TimeoutSeconds: int(to.Seconds()), MaxConcurrency: spec.MaxConcurrency,
		Scopes: append([]string{}, spec.Scopes...), Enabled: true, CreatedBy: by, CreatedAt: s.now(),
	}
	if f.Cron != "" {
		now := s.now()
		f.LastCronAt = &now // first fire is the next scheduled time, not a catch-up
	}
	if err := s.Store.CreateFunction(ctx, f); err != nil {
		return nil, err
	}
	return f, nil
}

// Enqueue puts a run in the queue. The scopes are a snapshot of what the function declared.
func (s *Service) Enqueue(ctx context.Context, f *Function, trigger, by string, payload json.RawMessage) (*Run, error) {
	if !f.Enabled {
		return nil, ErrDisabled
	}
	if f.VPNID != nil {
		t, err := s.VPN.Store.GetByID(ctx, *f.VPNID)
		if err != nil || !t.Enabled {
			return nil, fmt.Errorf("%w: tunnel is off", ErrDisabled)
		}
	}
	r := &Run{ID: uuid.New(), FunctionID: f.ID, ProjectID: f.ProjectID, Trigger: trigger, TriggeredBy: by, Status: RunQueued,
		QueuedAt: s.now(), Scopes: append([]string{}, f.Scopes...), Payload: payload}
	if err := s.Store.EnqueueRun(ctx, r); err != nil {
		return nil, err
	}
	return r, nil
}

// Tick fires due crons and reaps runs whose node vanished. Safe to call every minute from several instances.
func (s *Service) Tick(ctx context.Context) error {
	now := s.now()
	fs, err := s.Store.CronFunctions(ctx)
	if err != nil {
		return err
	}
	for _, f := range fs {
		if !f.Enabled || f.Cron == "" {
			continue
		}
		sched, err := ParseCron(f.Cron)
		if err != nil {
			continue
		}
		base := f.CreatedAt
		if f.LastCronAt != nil {
			base = *f.LastCronAt
		}
		if next := sched.Next(base); next.After(now) {
			continue
		}
		ok, err := s.Store.CASLastCron(ctx, f.ID, f.LastCronAt, now)
		if err != nil || !ok {
			continue
		}
		// Overlap: a cron never piles up behind a running instance; at most one waits in the queue.
		if q, _ := s.Store.QueuedRuns(ctx, 1000); hasQueued(q, f.ID) {
			continue
		}
		_, _ = s.Enqueue(ctx, f, TriggerCron, "cron", nil)
	}
	running, err := s.Store.RunningRuns(ctx)
	if err != nil {
		return err
	}
	for _, r := range running {
		f, err := s.Store.GetFunctionByID(ctx, r.FunctionID)
		if err != nil || r.StartedAt == nil {
			continue
		}
		limit := time.Duration(f.TimeoutSeconds)*time.Second + TokenGrace
		if now.Sub(*r.StartedAt) > limit {
			_ = s.finish(ctx, r, RunTimeout, nil, r.BytesIn, r.BytesOut, "reaped: the node stopped reporting")
		}
	}
	return nil
}

func hasQueued(q []*Run, fid uuid.UUID) bool {
	for _, r := range q {
		if r.FunctionID == fid {
			return true
		}
	}
	return false
}

// TunnelAssignment is what the gateway needs; it is the only place decrypted credentials leave the backend,
// and only for a node authenticated with its own token.
type TunnelAssignment struct {
	ID           uuid.UUID `json:"id"`
	Provider     string    `json:"provider"`
	Host         string    `json:"host"`
	CIDRs        []string  `json:"cidrs"`
	CertPin      string    `json:"cert_pin,omitempty"`
	MaxConns     int       `json:"max_conns"`
	BandwidthBps int64     `json:"bandwidth_bps"`
	Version      int64     `json:"version"` // unix nanos of updated_at: a change restarts the gateway
	Secret       string    `json:"secret"`
}

// Assignment is a claimed run.
type Assignment struct {
	Run      *Run              `json:"run"`
	Function *Function         `json:"function"`
	Tunnel   *TunnelAssignment `json:"tunnel,omitempty"`
	Token    string            `json:"token"`
	APIBase  string            `json:"api_base"`
	Env      map[string]string `json:"env"`
}

// Claim hands the oldest runnable run to a node, or nil when there is none. The function never gets the tunnel secret.
func (s *Service) Claim(ctx context.Context, node string) (*Assignment, error) {
	queued, err := s.Store.QueuedRuns(ctx, 50)
	if err != nil {
		return nil, err
	}
	for _, r := range queued {
		f, err := s.Store.GetFunctionByID(ctx, r.FunctionID)
		if err != nil || !f.Enabled || f.Runtime == RuntimeLambda {
			continue // lambda runs are executed by the backend (DispatchLambda), never by a node
		}
		var ta *TunnelAssignment
		if f.VPNID != nil {
			t, err := s.VPN.Store.GetByID(ctx, *f.VPNID)
			if err != nil || !t.Enabled || t.ProjectID != f.ProjectID {
				continue // the tunnel is off (kill switch) or not of this project: no credentials leave
			}
			sec, err := s.VPN.Secret(t)
			if err != nil {
				continue
			}
			ta = &TunnelAssignment{ID: t.ID, Provider: t.Provider, Host: t.Host, CIDRs: t.CIDRs, CertPin: t.CertPin,
				MaxConns: t.MaxConns, BandwidthBps: t.BandwidthBps, Version: t.UpdatedAt.UnixNano(), Secret: sec}
		}
		ok, err := s.Store.TryStart(ctx, r.ID, node, s.now())
		if err != nil || !ok {
			continue // function already at max_concurrency
		}
		plain, hash := NewToken(TokenPrefix)
		exp := s.now().Add(time.Duration(f.TimeoutSeconds)*time.Second + TokenGrace)
		if err := s.Store.PutToken(ctx, RunToken{Hash: hash, RunID: r.ID, ProjectID: r.ProjectID, Scopes: r.Scopes, ExpiresAt: exp}); err != nil {
			_ = s.Store.FinishRun(ctx, r.ID, RunFailed, nil, 0, 0, "could not mint run token", s.now())
			continue
		}
		run, _ := s.Store.GetRun(ctx, r.ID)
		if ta != nil {
			if t, err := s.VPN.Store.GetByID(ctx, ta.ID); err == nil {
				s.VPN.Audit(ctx, t, vpn.EventRunStarted, fmt.Sprintf("function %s run %s started (%s by %s); scopes %s", f.Name, r.ID, r.Trigger, r.TriggeredBy, strings.Join(r.Scopes, ",")), "node:"+node)
			}
		}
		env := s.runEnv(ctx, f, r, plain, false)
		return &Assignment{Run: run, Function: f, Tunnel: ta, Token: plain, APIBase: s.APIBase, Env: env}, nil
	}
	return nil, nil
}

// runEnv is the environment of a run: the token, its scopes, the payload and the resources (databases, buckets) its scopes name.
// public is true for runs outside the host (Lambda): buckets are then reached by their public endpoint instead of the internal route.
func (s *Service) runEnv(ctx context.Context, f *Function, r *Run, plain string, public bool) map[string]string {
	env := map[string]string{
		"CAPSULE_RUN_ID": r.ID.String(), "CAPSULE_FN": f.Name, "CAPSULE_API": s.APIBase, "CAPSULE_TOKEN": plain,
		"CAPSULE_SCOPES": strings.Join(r.Scopes, ","),
	}
	if r.Payload != nil {
		env["CAPSULE_PAYLOAD"] = string(r.Payload)
	}
	for _, sc := range r.Scopes { // only databases named in the function's scopes
		if name, ok := strings.CutPrefix(sc, "db:"); ok && s.DBs != nil {
			if u, err := s.DBs(ctx, r.ProjectID, name); err == nil {
				env["CAPSULE_DB_"+strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name))] = u
			}
		}
	}
	for _, sc := range r.Scopes {
		if name, ok := strings.CutPrefix(sc, "storage:"); ok && s.Storage != nil {
			if kv, err := s.Storage(ctx, r.ProjectID, name); err == nil {
				p := "CAPSULE_STORAGE_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(name)) + "_"
				for k, v := range kv {
					if k != "public_endpoint" {
						env[p+strings.ToUpper(k)] = v
					}
				}
				if pub := kv["public_endpoint"]; public && pub != "" {
					env[p+"ENDPOINT"] = pub
				}
			}
		}
	}
	return env
}

// SyncReply tells the node what to stop.
type SyncReply struct {
	CancelRuns  []uuid.UUID `json:"cancel_runs"`
	StopTunnels []uuid.UUID `json:"stop_tunnels"`
	// Relay lists the tunnels this node must keep up and attach to the relay because a Lambda run of this node uses them.
	Relay []TunnelAssignment `json:"relay,omitempty"`
}

// Sync is the node's heartbeat: it lists the runs it executes and the tunnels it keeps up, and learns what to kill.
func (s *Service) Sync(ctx context.Context, node string, running []uuid.UUID, tunnels []uuid.UUID) (SyncReply, error) {
	rep := SyncReply{CancelRuns: []uuid.UUID{}, StopTunnels: []uuid.UUID{}}
	for _, id := range running {
		r, err := s.Store.GetRun(ctx, id)
		if err != nil || r.Status != RunRunning {
			rep.CancelRuns = append(rep.CancelRuns, id)
		}
	}
	for _, id := range tunnels {
		t, err := s.VPN.Store.GetByID(ctx, id)
		if err != nil || !t.Enabled {
			rep.StopTunnels = append(rep.StopTunnels, id)
		}
	}
	relay, err := s.RelayTunnels(ctx, node)
	if err != nil {
		return rep, err
	}
	rep.Relay = relay
	return rep, nil
}

// Finish records the end of a run reported by the node.
func (s *Service) Finish(ctx context.Context, runID uuid.UUID, status string, exit *int, in, out int64, tail string) error {
	r, err := s.Store.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	if r.Status != RunRunning {
		return nil // already cancelled/reaped; the first terminal state wins
	}
	return s.finish(ctx, r, status, exit, in, out, tail)
}

func (s *Service) finish(ctx context.Context, r *Run, status string, exit *int, in, out int64, tail string) error {
	if err := s.Store.FinishRun(ctx, r.ID, status, exit, in, out, tail, s.now()); err != nil {
		return err
	}
	_ = s.Store.RevokeRunTokens(ctx, r.ID, s.now())
	s.stopLambda(r.ID) // a Lambda run in flight: stop invoking, cut its relay connections
	if f, err := s.Store.GetFunctionByID(ctx, r.FunctionID); err == nil && f.VPNID != nil {
		if t, err := s.VPN.Store.GetByID(ctx, *f.VPNID); err == nil {
			s.VPN.Audit(ctx, t, vpn.EventRunFinished, fmt.Sprintf("function %s run %s %s; bytes in %d out %d; scopes %s", f.Name, r.ID, status, in, out, strings.Join(r.Scopes, ",")), "node:"+r.NodeID)
		}
	}
	return nil
}

// Cancel stops a run (queued or running).
func (s *Service) Cancel(ctx context.Context, r *Run) error {
	if r.Status != RunQueued && r.Status != RunRunning {
		return nil
	}
	return s.finish(ctx, r, RunCancelled, nil, r.BytesIn, r.BytesOut, "cancelled")
}

// DisableTunnel is the kill switch: tunnel off and every run that uses it cancelled and its tokens revoked.
func (s *Service) DisableTunnel(ctx context.Context, t *vpn.Tunnel, actor string) error {
	if err := s.VPN.SetEnabled(ctx, t, false, actor); err != nil {
		return err
	}
	if s.Relay != nil {
		s.Relay.DropTunnel(t.ID.String()) // idle node connections of the relay go too
	}
	for _, list := range []func(context.Context) ([]*Run, error){s.Store.RunningRuns, func(c context.Context) ([]*Run, error) { return s.Store.QueuedRuns(c, 1000) }} {
		runs, err := list(ctx)
		if err != nil {
			return err
		}
		for _, r := range runs {
			if f, err := s.Store.GetFunctionByID(ctx, r.FunctionID); err == nil && f.VPNID != nil && *f.VPNID == t.ID {
				_ = s.Cancel(ctx, r)
			}
		}
	}
	return nil
}

// Introspect validates a run token for the customer's app. Inactive for unknown, expired, revoked or finished runs.
func (s *Service) Introspect(ctx context.Context, plain string) Claims {
	if !strings.HasPrefix(plain, TokenPrefix) {
		return Claims{}
	}
	t, err := s.Store.GetToken(ctx, HashToken(plain))
	if err != nil || t.RevokedAt != nil || !s.now().Before(t.ExpiresAt) {
		return Claims{}
	}
	r, err := s.Store.GetRun(ctx, t.RunID)
	if err != nil || r.Status != RunRunning {
		return Claims{}
	}
	f, err := s.Store.GetFunctionByID(ctx, r.FunctionID)
	if err != nil {
		return Claims{}
	}
	return Claims{Active: true, ProjectID: t.ProjectID, Function: f.Name, RunID: r.ID, Scopes: t.Scopes, ExpiresAt: t.ExpiresAt}
}
