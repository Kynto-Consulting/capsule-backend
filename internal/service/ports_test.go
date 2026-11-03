package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/netaccess"
)

// ---- fakes ----------------------------------------------------------------

type fakePortRepo struct {
	mu          sync.Mutex
	ports       map[uuid.UUID][]*domain.ProjectPort
	foreignUsed map[int]bool // ports used by databases/deployments
	replaceErr  error
}

func newFakePortRepo() *fakePortRepo {
	return &fakePortRepo{ports: map[uuid.UUID][]*domain.ProjectPort{}, foreignUsed: map[int]bool{}}
}

func (f *fakePortRepo) List(_ context.Context, pid uuid.UUID) ([]*domain.ProjectPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*domain.ProjectPort{}, f.ports[pid]...), nil
}

func (f *fakePortRepo) UsedHostPorts(_ context.Context, from, to int) (map[int]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[int]bool{}
	for p := range f.foreignUsed {
		out[p] = true
	}
	for _, ps := range f.ports {
		for _, p := range ps {
			out[p.HostPort] = true
		}
	}
	return out, nil
}

func (f *fakePortRepo) Replace(_ context.Context, pid uuid.UUID, ports []*domain.ProjectPort) ([]*domain.ProjectPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.replaceErr != nil {
		return nil, f.replaceErr
	}
	var out []*domain.ProjectPort
	for _, p := range ports {
		c := *p
		if c.ID == uuid.Nil {
			c.ID = uuid.New()
		}
		if c.Rules == nil {
			c.Rules = []*domain.PortRule{}
		}
		out = append(out, &c)
	}
	f.ports[pid] = out
	return append([]*domain.ProjectPort{}, out...), nil
}

func (f *fakePortRepo) AddRule(_ context.Context, pid uuid.UUID, cp int, rule *domain.PortRule, max int) (*domain.PortRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.ports[pid] {
		if p.ContainerPort != cp {
			continue
		}
		if len(p.Rules) >= max {
			return nil, domain.ErrRuleLimit
		}
		for _, r := range p.Rules {
			if r.CIDR == rule.CIDR {
				return nil, domain.ErrConflict
			}
		}
		c := *rule
		c.ID = uuid.New()
		p.Rules = append(p.Rules, &c)
		return &c, nil
	}
	return nil, domain.ErrNotFound
}

func (f *fakePortRepo) DeleteRule(_ context.Context, pid, ruleID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.ports[pid] {
		for i, r := range p.Rules {
			if r.ID == ruleID {
				p.Rules = append(p.Rules[:i], p.Rules[i+1:]...)
				return nil
			}
		}
	}
	return domain.ErrNotFound
}

func (f *fakePortRepo) ListDesired(context.Context) ([]domain.DesiredPortRule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.DesiredPortRule
	for pid, ps := range f.ports {
		for _, p := range ps {
			for _, r := range p.Rules {
				out = append(out, domain.DesiredPortRule{ProjectID: pid, HostPort: p.HostPort, CIDR: r.CIDR})
			}
		}
	}
	return out, nil
}

func (f *fakePortRepo) DeleteAll(_ context.Context, pid uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.ports, pid)
	return nil
}

type fakeFirewall struct {
	reconciled [][]netaccess.PortDesired
	synced     [][]netaccess.PortDesired
	err        error
}

func (f *fakeFirewall) ReconcileProjectPorts(_ context.Context, _ uuid.UUID, d []netaccess.PortDesired) error {
	if f.err != nil {
		return f.err
	}
	f.reconciled = append(f.reconciled, d)
	return nil
}

func (f *fakeFirewall) SyncAllPorts(_ context.Context, d []netaccess.PortDesired) error {
	f.synced = append(f.synced, d)
	return nil
}

type fakeRestarter struct {
	calls   [][]domain.PortMapping
	failOn  map[int]error // 1-based call index -> error
	nothing bool
}

func (f *fakeRestarter) Recreate(_ context.Context, _ uuid.UUID, extra []domain.PortMapping) error {
	f.calls = append(f.calls, append([]domain.PortMapping(nil), extra...))
	if f.nothing {
		return ErrNothingToRestart
	}
	return f.failOn[len(f.calls)]
}

func newTestPorts(repo *fakePortRepo, fw PortsFirewall, rs PortsRestarter) *PortsService {
	return NewPortsService(repo, fw, rs, PortsConfig{
		From: 41000, To: 41009, Host: "tcp.example.test",
		Reserved:  []int{8080},
		AvoidHost: [][2]int{{41003, 41004}},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func specs(ports ...int) []domain.PortSpec {
	var out []domain.PortSpec
	for _, p := range ports {
		out = append(out, domain.PortSpec{Name: "p", ContainerPort: p})
	}
	return out
}

func hostPorts(ps []*domain.ProjectPort) map[int]int {
	m := map[int]int{}
	for _, p := range ps {
		m[p.ContainerPort] = p.HostPort
	}
	return m
}

func code(err error) string {
	var pe *PortsError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// ---- tests ----------------------------------------------------------------

func TestParsePortRange(t *testing.T) {
	if f, to, err := ParsePortRange(""); err != nil || f != 41000 || to != 41999 {
		t.Fatalf("default: %d %d %v", f, to, err)
	}
	for _, bad := range []string{"x", "41000", "500-600", "42000-41000", "41000-70000"} {
		if _, _, err := ParsePortRange(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestHostPortsAreStableAndCollisionFree(t *testing.T) {
	repo := newFakePortRepo()
	repo.foreignUsed[41000] = true // a database/deployment owns it
	s := newTestPorts(repo, &fakeFirewall{}, &fakeRestarter{})
	a, b := uuid.New(), uuid.New()

	got, err := s.Replace(context.Background(), a, specs(5432, 6379))
	if err != nil {
		t.Fatal(err)
	}
	hp := hostPorts(got)
	// 41000 used by others, 41003-41004 avoided (db range): lowest free are 41001, 41002.
	if hp[5432] != 41001 || hp[6379] != 41002 {
		t.Fatalf("assignment = %v", hp)
	}
	// Another project never collides.
	gotB, err := s.Replace(context.Background(), b, specs(5432))
	if err != nil {
		t.Fatal(err)
	}
	if gotB[0].HostPort != 41005 {
		t.Fatalf("project b got %d, want 41005 (skipping used and avoided ports)", gotB[0].HostPort)
	}
	// Re-applying with an extra port keeps the existing host ports.
	got2, err := s.Replace(context.Background(), a, specs(5432, 6379, 9000))
	if err != nil {
		t.Fatal(err)
	}
	hp2 := hostPorts(got2)
	if hp2[5432] != 41001 || hp2[6379] != 41002 || hp2[9000] == 0 || hp2[9000] == 41005 {
		t.Fatalf("after adding: %v", hp2)
	}
	// Removing a port and re-adding another keeps survivors stable.
	got3, err := s.Replace(context.Background(), a, specs(6379))
	if err != nil || hostPorts(got3)[6379] != 41002 {
		t.Fatalf("after removing: %v %v", hostPorts(got3), err)
	}
}

func TestHostPortInUseProbeIsSkipped(t *testing.T) {
	repo := newFakePortRepo()
	s := newTestPorts(repo, &fakeFirewall{}, &fakeRestarter{})
	s.cfg.InUse = func(p int) bool { return p == 41000 }
	got, err := s.Replace(context.Background(), uuid.New(), specs(5432))
	if err != nil || got[0].HostPort != 41001 {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestRangeExhausted(t *testing.T) {
	repo := newFakePortRepo()
	s := newTestPorts(repo, &fakeFirewall{}, &fakeRestarter{})
	s.cfg.To = 41001
	_, err := s.Replace(context.Background(), uuid.New(), specs(1001, 1002, 1003))
	if code(err) != "PORT_RANGE_EXHAUSTED" {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateSpecsReservedAndLimits(t *testing.T) {
	s := newTestPorts(newFakePortRepo(), &fakeFirewall{}, nil)
	for _, p := range []int{22, 2375, 2376, 8080} {
		_, err := s.ValidateSpecs([]PortInput{{ContainerPort: p}})
		if code(err) != "RESERVED_PORT" {
			t.Errorf("port %d: err = %v", p, err)
		}
	}
	for _, p := range []int{0, -1, 65536} {
		if _, err := s.ValidateSpecs([]PortInput{{ContainerPort: p}}); code(err) != "INVALID_PORT" {
			t.Errorf("port %d: err = %v", p, err)
		}
	}
	if _, err := s.ValidateSpecs([]PortInput{{ContainerPort: 5432}, {ContainerPort: 5432}}); code(err) != "DUPLICATE_PORT" {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := s.ValidateSpecs([]PortInput{{ContainerPort: 5432, Protocol: "udp"}}); code(err) != "INVALID_PROTOCOL" {
		t.Errorf("udp: %v", err)
	}
	if _, err := s.ValidateSpecs([]PortInput{{ContainerPort: 5432, Name: strings.Repeat("a", 41)}}); code(err) != "INVALID_NAME" {
		t.Errorf("long name: %v", err)
	}
	var many []PortInput
	for i := 0; i < MaxPortsPerProject; i++ {
		many = append(many, PortInput{ContainerPort: 3000 + i})
	}
	if out, err := s.ValidateSpecs(many); err != nil || len(out) != 10 {
		t.Fatalf("10 ports must be accepted: %v", err)
	}
	many = append(many, PortInput{ContainerPort: 4000})
	_, err := s.ValidateSpecs(many)
	var pe *PortsError
	if !errors.As(err, &pe) || pe.Code != "LIMIT_EXCEEDED" || pe.Status != http.StatusUnprocessableEntity {
		t.Fatalf("11 ports: %v", err)
	}
	if out, err := s.ValidateSpecs([]PortInput{{ContainerPort: 1}, {ContainerPort: 65535, Name: "x", Protocol: "TCP"}}); err != nil || out[0].Name != "port-1" {
		t.Fatalf("edges: %v %v", out, err)
	}
	if out, err := s.ValidateSpecs(nil); err != nil || len(out) != 0 {
		t.Fatalf("empty list is valid: %v", err)
	}
}

func TestReplaceRestartsContainerWithNewPorts(t *testing.T) {
	repo := newFakePortRepo()
	rs := &fakeRestarter{}
	s := newTestPorts(repo, &fakeFirewall{}, rs)
	pid := uuid.New()
	if _, err := s.Replace(context.Background(), pid, specs(5432)); err != nil {
		t.Fatal(err)
	}
	if len(rs.calls) != 1 || len(rs.calls[0]) != 1 || rs.calls[0][0] != (domain.PortMapping{ContainerPort: 5432, HostPort: 41000}) {
		t.Fatalf("calls = %v", rs.calls)
	}
	// Rename only: no restart.
	if _, err := s.Replace(context.Background(), pid, []domain.PortSpec{{Name: "pg", ContainerPort: 5432}}); err != nil {
		t.Fatal(err)
	}
	if len(rs.calls) != 1 {
		t.Fatalf("a rename must not restart the container: %v", rs.calls)
	}
}

func TestReplaceRollsBackWhenRestartFails(t *testing.T) {
	repo := newFakePortRepo()
	rs := &fakeRestarter{}
	fw := &fakeFirewall{}
	s := newTestPorts(repo, fw, rs)
	pid := uuid.New()
	if _, err := s.Replace(context.Background(), pid, specs(5432)); err != nil {
		t.Fatal(err)
	}
	before := hostPorts(repo.ports[pid])

	rs.calls = nil
	rs.failOn = map[int]error{1: errors.New("docker run failed: port is already allocated")}
	_, err := s.Replace(context.Background(), pid, specs(5432, 6379))
	if code(err) != "RESTART_FAILED" || !strings.Contains(err.Error(), "previous configuration was restored") {
		t.Fatalf("err = %v", err)
	}
	// Call 1 = new ports (failed), call 2 = rollback with the OLD mapping.
	if len(rs.calls) != 2 || len(rs.calls[1]) != 1 || rs.calls[1][0].ContainerPort != 5432 {
		t.Fatalf("calls = %v", rs.calls)
	}
	after := hostPorts(repo.ports[pid])
	if len(after) != 1 || after[5432] != before[5432] {
		t.Fatalf("state changed after a failed restart: %v -> %v", before, after)
	}
}

func TestReplaceReportsFailedRollback(t *testing.T) {
	repo := newFakePortRepo()
	rs := &fakeRestarter{failOn: map[int]error{1: errors.New("boom"), 2: errors.New("still broken")}}
	s := newTestPorts(repo, &fakeFirewall{}, rs)
	_, err := s.Replace(context.Background(), uuid.New(), specs(5432))
	if code(err) != "RESTART_FAILED" || !strings.Contains(err.Error(), "also failed") || !strings.Contains(err.Error(), "still broken") {
		t.Fatalf("err = %v", err)
	}
}

func TestReplaceWithoutDeploymentOnlyStores(t *testing.T) {
	repo := newFakePortRepo()
	rs := &fakeRestarter{nothing: true}
	s := newTestPorts(repo, &fakeFirewall{}, rs)
	pid := uuid.New()
	got, err := s.Replace(context.Background(), pid, specs(5432))
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v %v", got, err)
	}
	if len(rs.calls) != 1 {
		t.Fatalf("calls = %v (no rollback expected when nothing was restarted)", rs.calls)
	}
}

func TestReplaceRollsBackWhenPersistFails(t *testing.T) {
	repo := newFakePortRepo()
	rs := &fakeRestarter{}
	s := newTestPorts(repo, &fakeFirewall{}, rs)
	repo.replaceErr = errors.New("db down")
	_, err := s.Replace(context.Background(), uuid.New(), specs(5432))
	if err == nil || len(rs.calls) != 2 {
		t.Fatalf("err=%v calls=%v: container must be restored when saving fails", err, rs.calls)
	}
}

func TestReplaceRemovingPortRevokesItsRulesAndRollsBackOnFirewallError(t *testing.T) {
	repo := newFakePortRepo()
	fw := &fakeFirewall{}
	rs := &fakeRestarter{}
	s := newTestPorts(repo, fw, rs)
	pid := uuid.New()
	if _, err := s.Replace(context.Background(), pid, specs(5432, 6379)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRule(context.Background(), pid, 5432, "203.0.113.5/32", "", uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddRule(context.Background(), pid, 6379, "198.51.100.0/24", "", uuid.New()); err != nil {
		t.Fatal(err)
	}
	fw.reconciled = nil
	if _, err := s.Replace(context.Background(), pid, specs(5432)); err != nil {
		t.Fatal(err)
	}
	last := fw.reconciled[len(fw.reconciled)-1]
	if len(last) != 1 || last[0].CIDR != "203.0.113.5/32" {
		t.Fatalf("desired after removal = %+v (the rule of the removed port must go)", last)
	}
	// Firewall refuses: container restored, nothing persisted.
	fw.err = errors.New("AWS down")
	rs.calls = nil
	_, err := s.Replace(context.Background(), pid, specs(5432, 7000))
	if code(err) != "FIREWALL_ERROR" || len(rs.calls) != 2 || len(repo.ports[pid]) != 1 {
		t.Fatalf("err=%v calls=%v ports=%d", err, rs.calls, len(repo.ports[pid]))
	}
}

func TestAddRuleAWSFirstThenPersist(t *testing.T) {
	repo := newFakePortRepo()
	fw := &fakeFirewall{}
	s := newTestPorts(repo, fw, &fakeRestarter{})
	pid := uuid.New()
	if _, err := s.Replace(context.Background(), pid, specs(5432)); err != nil {
		t.Fatal(err)
	}
	fw.err = errors.New("AWS refuses")
	_, err := s.AddRule(context.Background(), pid, 5432, "203.0.113.5/32", "office", uuid.New())
	if code(err) != "FIREWALL_ERROR" {
		t.Fatalf("err = %v", err)
	}
	if len(repo.ports[pid][0].Rules) != 0 {
		t.Fatal("rule persisted although AWS refused")
	}
	fw.err = nil
	rule, err := s.AddRule(context.Background(), pid, 5432, "203.0.113.5/32", " office ", uuid.New())
	if err != nil || rule.Description != "office" {
		t.Fatalf("rule=%v err=%v", rule, err)
	}
	d := fw.reconciled[len(fw.reconciled)-1]
	if len(d) != 1 || d[0].HostPort != 41000 || d[0].CIDR != "203.0.113.5/32" {
		t.Fatalf("desired = %+v", d)
	}
	if _, err := s.AddRule(context.Background(), pid, 5432, "203.0.113.5/32", "", uuid.New()); code(err) != "ALREADY_EXISTS" {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := s.AddRule(context.Background(), pid, 9999, "10.0.0.0/8", "", uuid.New()); code(err) != "NOT_FOUND" {
		t.Fatalf("unknown port: %v", err)
	}
	if err := s.RemoveRule(context.Background(), pid, 5432, rule.ID); err != nil {
		t.Fatal(err)
	}
	if last := fw.reconciled[len(fw.reconciled)-1]; len(last) != 0 {
		t.Fatalf("after remove desired = %+v", last)
	}
	if err := s.RemoveRule(context.Background(), pid, 5432, rule.ID); code(err) != "NOT_FOUND" {
		t.Fatalf("remove twice: %v", err)
	}
}

func TestAddRuleLimit(t *testing.T) {
	repo := newFakePortRepo()
	s := newTestPorts(repo, &fakeFirewall{}, &fakeRestarter{})
	pid := uuid.New()
	if _, err := s.Replace(context.Background(), pid, specs(5432)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < netaccess.MaxRulesPerPort; i++ {
		cidr := "10.0." + strconv.Itoa(i) + ".0/24"
		if _, err := s.AddRule(context.Background(), pid, 5432, cidr, "", uuid.New()); err != nil {
			t.Fatalf("rule %d: %v", i, err)
		}
	}
	_, err := s.AddRule(context.Background(), pid, 5432, "11.0.0.0/8", "", uuid.New())
	if code(err) != "LIMIT_EXCEEDED" {
		t.Fatalf("26th rule: %v", err)
	}
}

func TestCleanupAndSweep(t *testing.T) {
	repo := newFakePortRepo()
	fw := &fakeFirewall{}
	s := newTestPorts(repo, fw, &fakeRestarter{})
	pid := uuid.New()
	_, _ = s.Replace(context.Background(), pid, specs(5432))
	_, _ = s.AddRule(context.Background(), pid, 5432, "203.0.113.5/32", "", uuid.New())

	if err := s.Sweep(context.Background()); err != nil || len(fw.synced) != 1 || len(fw.synced[0]) != 1 {
		t.Fatalf("sweep: %v %v", err, fw.synced)
	}
	s.Cleanup(pid)
	if last := fw.reconciled[len(fw.reconciled)-1]; len(last) != 0 {
		t.Fatalf("cleanup desired = %+v", last)
	}
	if len(repo.ports[pid]) != 0 {
		t.Fatal("ports not deleted")
	}
	// Failed revoke keeps the rows so the startup sweep can retry.
	_, _ = s.Replace(context.Background(), pid, specs(5432))
	fw.err = errors.New("AWS down")
	s.Cleanup(pid)
	if len(repo.ports[pid]) != 1 {
		t.Fatal("ports deleted although revoke failed")
	}
}

func TestDisabledWithoutFirewall(t *testing.T) {
	s := NewPortsService(newFakePortRepo(), nil, nil, PortsConfig{From: 41000, To: 41999}, nil)
	if s.Enabled() {
		t.Fatal("must be disabled without a firewall")
	}
	s.Cleanup(uuid.New()) // must not panic
	if err := s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSupportsPorts(t *testing.T) {
	hp := 20123
	zero := 0
	cases := []struct {
		name    string
		project domain.Project
		dep     *domain.Deployment
		fargate bool
		want    bool
	}{
		{"docker deployment", domain.Project{BuildStrategy: "fargate"}, &domain.Deployment{HostPort: &hp}, true, true},
		{"fargate deployment", domain.Project{BuildStrategy: "fargate"}, &domain.Deployment{}, true, false},
		{"lambda deployment", domain.Project{BuildStrategy: "lambda"}, &domain.Deployment{HostPort: &zero}, false, false},
		{"no deploy, lambda", domain.Project{BuildStrategy: "lambda"}, nil, false, false},
		{"no deploy, static", domain.Project{BuildStrategy: "static"}, nil, false, false},
		{"no deploy, docker", domain.Project{BuildStrategy: "docker"}, nil, true, true},
		{"no deploy, default with fargate", domain.Project{}, nil, true, false},
		{"no deploy, default without fargate", domain.Project{}, nil, false, true},
	}
	for _, c := range cases {
		p := c.project
		if got := SupportsPorts(&p, c.dep, c.fargate); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// ---- docker side ------------------------------------------------------------

func TestDockerRunArgsPublishesExtraPorts(t *testing.T) {
	args := dockerRunArgs("capsule-app-x", "vol", "capsule-app-x", []string{"A=1"}, true, 3000, 20001,
		[]domain.PortMapping{{ContainerPort: 5432, HostPort: 41001}, {ContainerPort: 6379, HostPort: 41002}})
	joined := strings.Join(args, " ")
	for _, want := range []string{"-p 20001:3000", "-p 41001:5432", "-p 41002:6379", "-e A=1", "-e PORT=3000", "-v vol:/data"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	if args[len(args)-1] != "capsule-app-x" {
		t.Fatalf("image must be last: %v", args)
	}
	if strings.Contains(strings.Join(dockerRunArgs("n", "v", "i", nil, false, 3000, 20001, nil), " "), "PORT=") {
		t.Fatal("PORT must not be injected when the user set it")
	}
}

type fakeDeployRepo struct {
	domain.DeploymentRepository
	dep *domain.Deployment
}

func (f fakeDeployRepo) GetLatestSuccessfulByProject(context.Context, uuid.UUID) (*domain.Deployment, error) {
	if f.dep == nil {
		return nil, domain.ErrNotFound
	}
	return f.dep, nil
}

func TestDockerRestarterSequenceAndRollbackSafety(t *testing.T) {
	hp := 20500
	pid := uuid.New()
	dep := &domain.Deployment{ID: uuid.New(), ProjectID: pid, HostPort: &hp, ContainerPort: 3000}
	var cmds []string
	failRun := false
	missingImage := false
	d := &dockerRestarter{
		deployments: fakeDeployRepo{dep: dep},
		env:         func(context.Context, uuid.UUID, uuid.UUID) ([]string, error) { return []string{"K=v"}, nil },
		docker: func(_ context.Context, args ...string) ([]byte, error) {
			cmds = append(cmds, strings.Join(args, " "))
			if args[0] == "image" && missingImage {
				return []byte("no such image"), errors.New("exit 1")
			}
			if args[0] == "run" && failRun {
				return []byte("port is already allocated"), errors.New("exit 125")
			}
			return nil, nil
		},
	}
	extra := []domain.PortMapping{{ContainerPort: 5432, HostPort: 41001}}
	if err := d.Recreate(context.Background(), pid, extra); err != nil {
		t.Fatal(err)
	}
	if len(cmds) < 4 || !strings.HasPrefix(cmds[0], "image inspect") || !strings.HasPrefix(cmds[1], "rm -f") ||
		!strings.HasPrefix(cmds[2], "run -d") || !strings.Contains(cmds[2], "-p 20500:3000") || !strings.Contains(cmds[2], "-p 41001:5432") ||
		!strings.Contains(cmds[2], "-v capsule-data-"+pid.String()+":/data") || !strings.HasPrefix(cmds[3], "network connect") {
		t.Fatalf("commands = %v", cmds)
	}

	// Missing image: the running container must NOT be removed.
	cmds, missingImage = nil, true
	if err := d.Recreate(context.Background(), pid, extra); err == nil {
		t.Fatal("expected error")
	}
	for _, c := range cmds {
		if strings.HasPrefix(c, "rm ") {
			t.Fatalf("container removed although the image is missing: %v", cmds)
		}
	}

	// Run failure: error with docker output, half-created container cleaned.
	cmds, missingImage, failRun = nil, false, true
	err := d.Recreate(context.Background(), pid, extra)
	if err == nil || !strings.Contains(err.Error(), "already allocated") {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix(cmds[len(cmds)-1], "rm -f") {
		t.Fatalf("no cleanup after failed run: %v", cmds)
	}

	// No docker-on-host deployment: nothing to restart.
	d.deployments = fakeDeployRepo{}
	if err := d.Recreate(context.Background(), pid, extra); !errors.Is(err, ErrNothingToRestart) {
		t.Fatalf("err = %v", err)
	}
	fg := &domain.Deployment{ID: uuid.New()}
	d.deployments = fakeDeployRepo{dep: fg}
	if err := d.Recreate(context.Background(), pid, extra); !errors.Is(err, ErrNothingToRestart) {
		t.Fatalf("fargate deployment: %v", err)
	}
}

func TestDockerRestarterHonoursUserPortEnv(t *testing.T) {
	hp := 20500
	pid := uuid.New()
	dep := &domain.Deployment{ID: uuid.New(), HostPort: &hp, ContainerPort: 3000}
	var run string
	d := &dockerRestarter{
		deployments: fakeDeployRepo{dep: dep},
		env:         func(context.Context, uuid.UUID, uuid.UUID) ([]string, error) { return []string{"PORT=9090"}, nil },
		docker: func(_ context.Context, args ...string) ([]byte, error) {
			if args[0] == "run" {
				run = strings.Join(args, " ")
			}
			return nil, nil
		},
	}
	if err := d.Recreate(context.Background(), pid, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(run, "-p 20500:9090") || strings.Count(run, "PORT=") != 1 {
		t.Fatalf("run = %s", run)
	}
}
