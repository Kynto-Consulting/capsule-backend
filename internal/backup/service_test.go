package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

const testSecret = "unit-test-secret-key"

// ── fakes ───────────────────────────────────────────────────────────────────

type memStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	meta    map[string]map[string]string
	deleted []string
}

func newMemStore() *memStore {
	return &memStore{objects: map[string][]byte{}, meta: map[string]map[string]string{}}
}

func (m *memStore) Upload(_ context.Context, key string, meta map[string]string, r io.Reader) (int64, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return 0, err // like S3Store: nothing is created when the source fails
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key], m.meta[key] = b, meta
	return int64(len(b)), nil
}
func (m *memStore) Download(_ context.Context, key string) (io.ReadCloser, map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[key]
	if !ok {
		return nil, nil, errors.New("no such key")
	}
	return io.NopCloser(bytes.NewReader(b)), m.meta[key], nil
}
func (m *memStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	m.deleted = append(m.deleted, key)
	return nil
}
func (m *memStore) List(context.Context, string) ([]ObjectInfo, error) { return nil, nil }
func (m *memStore) keys() []string {
	var k []string
	for key := range m.objects {
		k = append(k, key)
	}
	sort.Strings(k)
	return k
}

type fakeRepo struct {
	mu        sync.Mutex
	settings  map[uuid.UUID]*Settings
	runs      []*Run
	snaps     []*Snapshot
	audits    []AuditEntry
	deploy    *ManifestInput
	claimWant []Run
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{settings: map[uuid.UUID]*Settings{}, deploy: &ManifestInput{EnvVarNames: []string{"DATABASE_URL", "API_KEY"}}}
}

func (f *fakeRepo) GetSettings(_ context.Context, id uuid.UUID) (*Settings, error) {
	return f.settings[id], nil
}
func (f *fakeRepo) UpsertSettings(_ context.Context, s *Settings) error {
	c := *s
	f.settings[s.ProjectID] = &c
	return nil
}
func (f *fakeRepo) ClaimDue(_ context.Context, _ bool, _ Settings, decide func(Candidate) bool) ([]Run, error) {
	var out []Run
	for id, s := range f.settings {
		id := id
		c := Candidate{ProjectID: &id, Settings: *s}
		for _, r := range f.runs {
			if r.ProjectID != nil && *r.ProjectID == id {
				t := r.StartedAt
				c.LastStart = &t
				c.Running = c.Running || r.Status == "running"
			}
		}
		if decide(c) {
			out = append(out, Run{ID: uuid.New(), ProjectID: &id, Kind: "backup", Trigger: "schedule", Status: "running", StartedAt: time.Now()})
		}
	}
	return out, nil
}
func (f *fakeRepo) CreateRun(_ context.Context, r *Run) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.runs {
		same := (x.ProjectID == nil && r.ProjectID == nil) || (x.ProjectID != nil && r.ProjectID != nil && *x.ProjectID == *r.ProjectID)
		if same && x.Status == "running" {
			return ErrRunInProgress
		}
	}
	c := *r
	f.runs = append(f.runs, &c)
	return nil
}
func (f *fakeRepo) FinishRun(_ context.Context, id uuid.UUID, status string, size int64, msg string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.runs {
		if r.ID == id {
			r.Status, r.SizeBytes, r.Error, r.FinishedAt = status, size, msg, &at
		}
	}
	return nil
}
func (f *fakeRepo) FailOrphans(_ context.Context, at time.Time) (int, error) {
	n := 0
	for _, r := range f.runs {
		if r.Status == "running" {
			r.Status, r.Error, r.FinishedAt = "failed", "interrupted", &at
			n++
		}
	}
	return n, nil
}
func (f *fakeRepo) ListRuns(context.Context, *uuid.UUID, int) ([]Run, error) {
	var out []Run
	for _, r := range f.runs {
		out = append(out, *r)
	}
	return out, nil
}
func (f *fakeRepo) LastBackupStart(context.Context, *uuid.UUID) (*time.Time, error) { return nil, nil }
func (f *fakeRepo) AddSnapshot(_ context.Context, s *Snapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := *s
	f.snaps = append(f.snaps, &c)
	return nil
}
func (f *fakeRepo) ListSnapshots(context.Context, *uuid.UUID) ([]Snapshot, error) {
	var out []Snapshot
	for _, s := range f.snaps {
		out = append(out, *s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}
func (f *fakeRepo) GetSnapshot(_ context.Context, pid *uuid.UUID, id uuid.UUID) (*Snapshot, error) {
	for _, s := range f.snaps {
		if s.ID == id && s.ProjectID != nil && pid != nil && *s.ProjectID == *pid {
			c := *s
			return &c, nil
		}
	}
	return nil, ErrNotFound
}
func (f *fakeRepo) ExpiredSnapshots(_ context.Context, _ *uuid.UUID, before time.Time) ([]Snapshot, error) {
	var out []Snapshot
	for _, s := range f.snaps {
		if s.CreatedAt.Before(before) {
			out = append(out, *s)
		}
	}
	return out, nil
}
func (f *fakeRepo) MarkSnapshotDeleted(_ context.Context, id uuid.UUID) error {
	for i, s := range f.snaps {
		if s.ID == id {
			f.snaps = append(f.snaps[:i], f.snaps[i+1:]...)
			return nil
		}
	}
	return nil
}
func (f *fakeRepo) LastDeployment(context.Context, uuid.UUID) (*ManifestInput, error) {
	c := *f.deploy
	return &c, nil
}
func (f *fakeRepo) Audit(_ context.Context, e AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.audits = append(f.audits, e)
	return nil
}
func (f *fakeRepo) run(id uuid.UUID) *Run {
	for _, r := range f.runs {
		if r.ID == id {
			return r
		}
	}
	return nil
}

type fakeDocker struct {
	mu       sync.Mutex
	calls    []Cmd
	stdin    map[int][]byte // plaintext read from Stdin per call index
	streams  int
	streamFn func(c Cmd) (io.ReadCloser, error)
	runFn    func(c Cmd) ([]byte, error)
}

func (d *fakeDocker) record(c Cmd) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, c)
	return len(d.calls) - 1
}
func (d *fakeDocker) Stream(_ context.Context, c Cmd) (io.ReadCloser, error) {
	d.record(c)
	d.mu.Lock()
	d.streams++
	d.mu.Unlock()
	return d.streamFn(c)
}
func (d *fakeDocker) Run(_ context.Context, c Cmd) ([]byte, error) {
	i := d.record(c)
	if c.Stdin != nil {
		b, err := io.ReadAll(c.Stdin)
		d.mu.Lock()
		if d.stdin == nil {
			d.stdin = map[int][]byte{}
		}
		d.stdin[i] = b
		d.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	if d.runFn != nil {
		if out, err := d.runFn(c); out != nil || err != nil {
			return out, err
		}
	}
	return []byte("[]"), nil
}
func (d *fakeDocker) joined() []string {
	var out []string
	for _, c := range d.calls {
		out = append(out, strings.Join(c.Args, " "))
	}
	return out
}
func (d *fakeDocker) find(sub string) int {
	for i, c := range d.calls {
		if strings.Contains(strings.Join(c.Args, " "), sub) {
			return i
		}
	}
	return -1
}

type closeErr struct {
	io.Reader
	err error
}

func (c closeErr) Close() error { return c.err }

func okStream(data string) io.ReadCloser { return closeErr{Reader: strings.NewReader(data)} }

type fakeProjects struct{ p *domain.Project }

func (f fakeProjects) GetByID(context.Context, uuid.UUID) (*domain.Project, error) { return f.p, nil }

type fakeDBs struct{ dbs []*domain.Database }

func (f fakeDBs) ListByProject(context.Context, uuid.UUID) ([]*domain.Database, error) {
	return f.dbs, nil
}

type env struct {
	svc   *Service
	repo  *fakeRepo
	store *memStore
	dock  *fakeDocker
	proj  *domain.Project
	dbs   *fakeDBs
}

const dbPassword = "p4ssw0rd-super-secret"

func newDB(t *testing.T, pid uuid.UUID, engine, name string) *domain.Database {
	t.Helper()
	creds, _ := json.Marshal(map[string]string{"username": "capsuleadmin", "password": dbPassword})
	enc, err := crypto.Encrypt(creds, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	return &domain.Database{ID: uuid.New(), ProjectID: &pid, Name: name, Engine: engine, Version: "16", Port: 41234,
		DBName: name, Status: "available", CredentialsEnc: enc}
}

func newEnv(t *testing.T, enabled bool, engines ...string) *env {
	t.Helper()
	pid, oid := uuid.New(), uuid.New()
	proj := &domain.Project{ID: pid, OrgID: oid, Slug: "shop", Runtime: "node", DeployType: "docker"}
	e := &env{repo: newFakeRepo(), store: newMemStore(), dock: &fakeDocker{}, proj: proj, dbs: &fakeDBs{}}
	for i, eng := range engines {
		e.dbs.dbs = append(e.dbs.dbs, newDB(t, pid, eng, fmt.Sprintf("db%d", i)))
	}
	e.dock.runFn = func(c Cmd) ([]byte, error) {
		a := strings.Join(c.Args, " ")
		if strings.HasPrefix(a, "inspect capsule-db-") {
			return []byte(`[{"Name":"/db","Config":{"Image":"postgres:16"},"HostConfig":{"RestartPolicy":{"Name":"unless-stopped"}},"Mounts":[{"Type":"volume","Name":"pgdata","Destination":"/var/lib/postgresql/data"}]}]`), nil
		}
		return nil, nil
	}
	e.dock.streamFn = func(c Cmd) (io.ReadCloser, error) { return okStream("PGDMP-very-secret-rows"), nil }
	e.svc = New(Config{Enabled: enabled, DefaultSchedule: "daily", DefaultOn: true, DefaultRetentionDays: 14, BucketRetentionDays: 30},
		e.repo, e.store, e.dock, fakeProjects{proj}, e.dbs, testSecret, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.svc.retryDelay = 0
	return e
}

// runNow creates a run and executes it synchronously.
func (e *env) runNow(t *testing.T, kind string, st Settings) *Run {
	t.Helper()
	pid, oid := e.proj.ID, e.proj.OrgID
	run := e.svc.newRun(&pid, &oid, kind, "manual", nil)
	if err := e.repo.CreateRun(context.Background(), &run); err != nil {
		t.Fatal(err)
	}
	st.ProjectID = pid
	e.svc.execute(run, st)
	return e.repo.run(run.ID)
}

func (e *env) plain(t *testing.T, key string) []byte {
	t.Helper()
	body, plain, err := openObject(context.Background(), e.store, testSecret, key)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	b, err := io.ReadAll(plain)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var allData = Settings{Enabled: true, Schedule: "daily", RetentionDays: 14, IncludeDatabases: true, IncludeVolumes: true}

// ── tests ───────────────────────────────────────────────────────────────────

func TestBackupStreamsEncryptedToStoreAndRecordsSnapshots(t *testing.T) {
	e := newEnv(t, true, "postgres")
	run := e.runNow(t, "backup", Settings{Enabled: true, IncludeDatabases: true, RetentionDays: 14})
	if run.Status != "success" {
		t.Fatalf("status %s: %s", run.Status, run.Error)
	}
	var dbSnap, manSnap *Snapshot
	for _, s := range e.repo.snaps {
		switch s.Kind {
		case "database":
			dbSnap = s
		case "manifest":
			manSnap = s
		}
	}
	if dbSnap == nil || manSnap == nil {
		t.Fatalf("want database and manifest snapshots, got %d", len(e.repo.snaps))
	}
	wantPrefix := "projects/" + e.proj.ID.String() + "/database/"
	if !strings.HasPrefix(dbSnap.ObjectKey, wantPrefix) || !strings.HasSuffix(dbSnap.ObjectKey, ".pgdump.enc") ||
		!strings.Contains(dbSnap.ObjectKey, run.ID.String()) {
		t.Fatalf("bad object key %s", dbSnap.ObjectKey)
	}
	raw := e.store.objects[dbSnap.ObjectKey]
	if bytes.Contains(raw, []byte("very-secret-rows")) {
		t.Fatal("stored object contains plaintext")
	}
	if got := e.plain(t, dbSnap.ObjectKey); string(got) != "PGDMP-very-secret-rows" {
		t.Fatalf("decrypted %q", got)
	}
	sum := sha256.Sum256([]byte("PGDMP-very-secret-rows"))
	if dbSnap.Checksum != hex.EncodeToString(sum[:]) || dbSnap.SourceID != e.dbs.dbs[0].ID.String() || dbSnap.Engine != "postgres" {
		t.Fatalf("snapshot metadata wrong: %+v", dbSnap)
	}
	if run.SizeBytes != dbSnap.SizeBytes+manSnap.SizeBytes {
		t.Fatalf("run size %d", run.SizeBytes)
	}
	if e.store.meta[dbSnap.ObjectKey][metaDEK] == "" {
		t.Fatal("wrapped data key missing from object metadata")
	}
	// credentials must never be in argv; only the variable NAME is
	for _, c := range e.dock.calls {
		for _, a := range c.Args {
			if strings.Contains(a, dbPassword) {
				t.Fatalf("password leaked into argv: %v", c.Args)
			}
		}
	}
	dump := e.dock.calls[e.dock.find("pg_dump")]
	if len(dump.Env) != 1 || dump.Env[0] != "PGPASSWORD="+dbPassword || !strings.Contains(strings.Join(dump.Args, " "), "-e PGPASSWORD ") {
		t.Fatalf("password must travel only in Env: %+v", dump)
	}
	// audit trail
	var actions []string
	for _, a := range e.repo.audits {
		actions = append(actions, a.Action)
	}
	if !strings.Contains(strings.Join(actions, ","), "backup.backup.start") || !strings.Contains(strings.Join(actions, ","), "backup.backup.finished") {
		t.Fatalf("audit actions %v", actions)
	}
}

func TestManifestHasReferencesButNoSecrets(t *testing.T) {
	e := newEnv(t, true, "postgres")
	e.repo.deploy = &ManifestInput{DeploymentID: uuid.New(), Version: "v7", ImageTag: "capsule-app-abc:v7", SourceKey: "deployments/p/x.tar.gz",
		ContainerPort: 3000, HostPort: 41001, DeployType: "docker", EnvVarNames: []string{"API_KEY", "DATABASE_URL"}}
	e.dock.runFn = func(c Cmd) ([]byte, error) {
		a := strings.Join(c.Args, " ")
		switch {
		case strings.HasPrefix(a, "image inspect"):
			return []byte(`[{"Id":"sha256:img","RepoDigests":["123.dkr.ecr/x@sha256:dig"]}]`), nil
		case strings.HasPrefix(a, "inspect capsule-app-"):
			return []byte(`[{"Name":"/capsule-app-x","Config":{"Image":"capsule-app-x","Env":["API_KEY=topsecretvalue"]},"HostConfig":{"RestartPolicy":{"Name":"unless-stopped"},"Memory":536870912},
			"Mounts":[{"Type":"volume","Name":"capsule-data-x","Destination":"/data"}],
			"NetworkSettings":{"Networks":{"capsule-prod_capsule-net":{}},"Ports":{"3000/tcp":[{"HostIp":"0.0.0.0","HostPort":"41001"}]}}}]`), nil
		case strings.HasPrefix(a, "inspect capsule-db-"):
			return []byte(`[{"Name":"/db","Config":{"Image":"postgres:16"},"HostConfig":{"RestartPolicy":{"Name":"unless-stopped"}},"Mounts":[{"Type":"volume","Name":"pgdata","Destination":"/var/lib/postgresql/data"}]}]`), nil
		}
		return nil, nil
	}
	run := e.runNow(t, "backup", Settings{Enabled: true, IncludeDatabases: false, RetentionDays: 14})
	if run.Status != "success" {
		t.Fatalf("%s", run.Error)
	}
	var key string
	for _, s := range e.repo.snaps {
		if s.Kind == "manifest" {
			key = s.ObjectKey
		}
	}
	if !strings.HasSuffix(key, ".json.enc") || !strings.Contains(key, "/manifest/") {
		t.Fatalf("manifest key %q", key)
	}
	raw := e.plain(t, key)
	for _, secret := range []string{dbPassword, "topsecretvalue"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("manifest leaks %q", secret)
		}
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Schema != 1 || m.Project.Slug != "shop" || m.Deployment == nil || m.Deployment.SourceKey != "deployments/p/x.tar.gz" ||
		m.Deployment.ImageID != "sha256:img" || len(m.Deployment.ImageDigests) != 1 || m.Deployment.HostPort != 41001 {
		t.Fatalf("manifest content: %+v", m)
	}
	if m.Container == nil || m.Container.RestartPolicy != "unless-stopped" || m.Container.MemoryBytes != 536870912 ||
		len(m.Container.Ports) != 1 || m.Container.Ports[0].HostPort != "41001" || m.Container.Networks[0] != "capsule-prod_capsule-net" {
		t.Fatalf("container: %+v", m.Container)
	}
	if len(m.Volumes) != 1 || m.Volumes[0].MountPoint != "/data" || strings.Join(m.EnvVarNames, ",") != "API_KEY,DATABASE_URL" {
		t.Fatalf("volumes/env: %+v %v", m.Volumes, m.EnvVarNames)
	}
	if len(m.Databases) != 1 || m.Databases[0].Engine != "postgres" || !m.Databases[0].Present || m.Databases[0].Container == "" ||
		m.Databases[0].HostPort != 41234 || len(m.Databases[0].Volumes) != 1 {
		t.Fatalf("databases: %+v", m.Databases)
	}
}

func TestFailedDumpRetriesOnceAndStoresNothing(t *testing.T) {
	e := newEnv(t, true, "postgres")
	e.dock.streamFn = func(Cmd) (io.ReadCloser, error) {
		return closeErr{Reader: strings.NewReader("partial"), err: errors.New("exit status 1: pg_dump: connection refused")}, nil
	}
	run := e.runNow(t, "backup", Settings{Enabled: true, IncludeDatabases: true, RetentionDays: 14})
	if run.Status != "failed" || !strings.Contains(run.Error, "connection refused") {
		t.Fatalf("status %s err %q", run.Status, run.Error)
	}
	if e.dock.streams != 2 {
		t.Fatalf("want exactly one retry (2 attempts), got %d", e.dock.streams)
	}
	for _, s := range e.repo.snaps {
		if s.Kind == "database" {
			t.Fatal("snapshot recorded for a failed dump")
		}
	}
	for k := range e.store.objects {
		if strings.Contains(k, "/database/") {
			t.Fatal("object stored for a failed dump")
		}
	}
	// the manifest succeeded on attempt 1 and must not be duplicated by the retry
	manifests := 0
	for _, s := range e.repo.snaps {
		if s.Kind == "manifest" {
			manifests++
		}
	}
	if manifests != 1 {
		t.Fatalf("manifest stored %d times", manifests)
	}
}

func TestRetrySucceedsOnSecondAttempt(t *testing.T) {
	e := newEnv(t, true, "postgres")
	n := 0
	e.dock.streamFn = func(Cmd) (io.ReadCloser, error) {
		n++
		if n == 1 {
			return nil, errors.New("docker daemon busy")
		}
		return okStream("DUMP"), nil
	}
	if run := e.runNow(t, "backup", Settings{Enabled: true, IncludeDatabases: true, RetentionDays: 14}); run.Status != "success" {
		t.Fatalf("%s %s", run.Status, run.Error)
	}
}

func TestUnsupportedEnginesAreMarkedNotInvented(t *testing.T) {
	e := newEnv(t, true, "cassandra")
	run := e.runNow(t, "backup", Settings{Enabled: true, IncludeDatabases: true, RetentionDays: 14})
	if run.Status != "failed" || !strings.Contains(run.Error, "not supported") || !strings.Contains(run.Error, "cassandra") {
		t.Fatalf("only-unsupported project must fail clearly: %s %q", run.Status, run.Error)
	}
	e2 := newEnv(t, true, "postgres", "clickhouse")
	run = e2.runNow(t, "backup", Settings{Enabled: true, IncludeDatabases: true, RetentionDays: 14})
	if run.Status != "success" || !strings.Contains(run.Error, "clickhouse") || !strings.Contains(run.Error, "not supported") {
		t.Fatalf("mixed project: %s %q", run.Status, run.Error)
	}
	if e2.dock.find("clickhouse") >= 0 && e2.dock.find("exec") >= 0 && strings.Contains(strings.Join(e2.dock.joined(), "\n"), "exec -i clickhouse") {
		t.Fatal("tried to dump an unsupported engine")
	}
}

func TestExternalDatabaseWithoutContainerIsSkipped(t *testing.T) {
	e := newEnv(t, true, "postgres")
	e.dock.runFn = func(c Cmd) ([]byte, error) {
		if strings.HasPrefix(strings.Join(c.Args, " "), "inspect capsule-db-") {
			return nil, errors.New("No such object")
		}
		return nil, nil
	}
	run := e.runNow(t, "backup", Settings{Enabled: true, IncludeDatabases: true, RetentionDays: 14})
	if !strings.Contains(run.Error, "managed externally") {
		t.Fatalf("%s %q", run.Status, run.Error)
	}
}

func TestEngineCommands(t *testing.T) {
	tg := DBTarget{Container: "c1", DBName: "app", User: "capsuleadmin", Password: "pw"}
	for _, name := range []string{"postgres", "mysql", "mariadb", "mongodb", "redis"} {
		eng, err := engineFor(name)
		if err != nil {
			t.Fatal(err)
		}
		c := eng.dump(tg)
		if strings.Contains(strings.Join(c.Args, " "), "pw") && name != "mysql" && name != "mariadb" { // "pw" substring check is for password leakage
			t.Errorf("%s: password in argv %v", name, c.Args)
		}
		if c.Args[0] != "exec" || c.Args[len(c.Args)-1] == "" {
			t.Errorf("%s: odd command %v", name, c.Args)
		}
	}
	if c := postgresEngine.dump(tg); !strings.Contains(strings.Join(c.Args, " "), "pg_dump --format=custom") {
		t.Errorf("postgres must use pg_dump --format=custom: %v", c.Args)
	}
	if c := mysqlEngine.dump(tg); !strings.Contains(strings.Join(c.Args, " "), "--single-transaction") {
		t.Errorf("mysql dump must be --single-transaction: %v", c.Args)
	}
	if c := mongoEngine.dump(tg); !strings.Contains(strings.Join(c.Args, " "), "--archive --gzip") {
		t.Errorf("mongo dump: %v", c.Args)
	}
	if redisEngine.restore != nil {
		t.Error("redis restore must be unsupported")
	}
	for _, name := range []string{"cassandra", "clickhouse", "elasticsearch", "cockroachdb", "graphql"} {
		if _, err := engineFor(name); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Errorf("%s should be unsupported", name)
		}
	}
}

func TestVolumeBackupUsesReadOnlyEphemeralHelper(t *testing.T) {
	e := newEnv(t, true)
	e.dock.streamFn = func(Cmd) (io.ReadCloser, error) { return okStream("TARGZ-DATA"), nil }
	run := e.runNow(t, "backup", Settings{Enabled: true, IncludeVolumes: true, RetentionDays: 14})
	if run.Status != "success" {
		t.Fatalf("%s %s", run.Status, run.Error)
	}
	var vol *Snapshot
	for _, s := range e.repo.snaps {
		if s.Kind == "volume" {
			vol = s
		}
	}
	if vol == nil || vol.Source != "capsule-data-"+e.proj.ID.String() || !strings.HasSuffix(vol.ObjectKey, ".tar.gz.enc") {
		t.Fatalf("volume snapshot %+v", vol)
	}
	args := strings.Join(e.dock.calls[e.dock.find("--rm")].Args, " ")
	for _, want := range []string{"--network none", "--read-only", "capsule-data-" + e.proj.ID.String() + ":/data:ro", "sqlite3", "tar"} {
		if !strings.Contains(args, want) {
			t.Errorf("helper command misses %q: %s", want, args)
		}
	}
	for _, bad := range []string{"docker.sock", "build-cache", "image prune"} {
		if strings.Contains(args, bad) {
			t.Errorf("helper must not touch %q", bad)
		}
	}
	if string(e.plain(t, vol.ObjectKey)) != "TARGZ-DATA" {
		t.Fatal("volume stream mismatch")
	}
}

func TestDisabledPlatformBlocksWritesAndScheduler(t *testing.T) {
	e := newEnv(t, false, "postgres")
	ctx := context.Background()
	if _, err := e.svc.StartBackup(ctx, e.proj.ID, nil); !errors.Is(err, ErrDisabled) {
		t.Fatalf("StartBackup: %v", err)
	}
	if _, err := e.svc.StartRestore(ctx, e.proj.ID, uuid.New(), "", nil); !errors.Is(err, ErrDisabled) {
		t.Fatalf("StartRestore: %v", err)
	}
	if _, err := e.svc.StartVerify(ctx, e.proj.ID, nil); !errors.Is(err, ErrDisabled) {
		t.Fatalf("StartVerify: %v", err)
	}
	if _, err := e.svc.StartPlatformBackup(ctx, nil); !errors.Is(err, ErrDisabled) {
		t.Fatalf("platform: %v", err)
	}
	if _, err := e.svc.Update(ctx, e.proj.ID, Patch{}); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Update: %v", err)
	}
	e.repo.runs = append(e.repo.runs, &Run{ID: uuid.New(), Status: "running"})
	e.svc.Run(ctx) // returns immediately: no scheduler, no orphan recovery
	if e.repo.runs[0].Status != "running" {
		t.Fatal("scheduler ran although backups are disabled")
	}
	v, err := e.svc.Get(ctx, e.proj.ID)
	if err != nil || v.Enabled || v.NextRun != nil {
		t.Fatalf("view when disabled: %+v %v", v, err)
	}
	if c := e.svc.Capability().(map[string]any); c["enabled"] != false || c["default_schedule"] != "daily" {
		t.Fatalf("capability %v", c)
	}
}

func TestOrphanedRunsAreFailedOnStartup(t *testing.T) {
	e := newEnv(t, true)
	pid := e.proj.ID
	e.repo.runs = append(e.repo.runs, &Run{ID: uuid.New(), ProjectID: &pid, Kind: "backup", Status: "running", StartedAt: time.Now()},
		&Run{ID: uuid.New(), ProjectID: &pid, Kind: "backup", Status: "success"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e.svc.Run(ctx)
	if e.repo.runs[0].Status != "failed" || e.repo.runs[0].FinishedAt == nil || e.repo.runs[1].Status != "success" {
		t.Fatalf("orphans: %+v %+v", e.repo.runs[0], e.repo.runs[1])
	}
}

func TestSchedulerDecisionAndOneRunAtATime(t *testing.T) {
	e := newEnv(t, true)
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	e.svc.now = func() time.Time { return now }
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	cases := []struct {
		name string
		c    Candidate
		want bool
	}{
		{"never ran", Candidate{Settings: Settings{Enabled: true, Schedule: "daily"}}, true},
		{"ran 2h ago daily", Candidate{Settings: Settings{Enabled: true, Schedule: "daily"}, LastStart: ago(2 * time.Hour)}, false},
		{"ran 25h ago daily", Candidate{Settings: Settings{Enabled: true, Schedule: "daily"}, LastStart: ago(25 * time.Hour)}, true},
		{"ran 61m ago hourly", Candidate{Settings: Settings{Enabled: true, Schedule: "hourly"}, LastStart: ago(61 * time.Minute)}, true},
		{"6h not yet", Candidate{Settings: Settings{Enabled: true, Schedule: "6h"}, LastStart: ago(5 * time.Hour)}, false},
		{"weekly 6d", Candidate{Settings: Settings{Enabled: true, Schedule: "weekly"}, LastStart: ago(6 * 24 * time.Hour)}, false},
		{"weekly 8d", Candidate{Settings: Settings{Enabled: true, Schedule: "weekly"}, LastStart: ago(8 * 24 * time.Hour)}, true},
		{"disabled", Candidate{Settings: Settings{Enabled: false, Schedule: "daily"}}, false},
		{"already running", Candidate{Settings: Settings{Enabled: true, Schedule: "hourly"}, Running: true}, false},
	}
	for _, c := range cases {
		if got := e.svc.decide(c.c); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	// a second manual run while one is running is rejected (one backup per project at a time)
	pid, oid := e.proj.ID, e.proj.OrgID
	r1 := e.svc.newRun(&pid, &oid, "backup", "manual", nil)
	r2 := e.svc.newRun(&pid, &oid, "restore", "manual", nil)
	if err := e.repo.CreateRun(context.Background(), &r1); err != nil {
		t.Fatal(err)
	}
	if err := e.repo.CreateRun(context.Background(), &r2); !errors.Is(err, ErrRunInProgress) {
		t.Fatalf("want ErrRunInProgress, got %v", err)
	}
}

func TestTickClaimsAndExecutesDueProjects(t *testing.T) {
	e := newEnv(t, true, "postgres")
	e.repo.settings[e.proj.ID] = &Settings{ProjectID: e.proj.ID, Enabled: true, Schedule: "daily", RetentionDays: 14, IncludeDatabases: true}
	e.svc.Tick(context.Background())
	if len(e.repo.snaps) == 0 {
		t.Fatal("tick did not back anything up")
	}
	// next tick: the project just ran, so it is not due again
	n := len(e.repo.snaps)
	e.repo.runs = nil
	pid := e.proj.ID
	e.repo.runs = append(e.repo.runs, &Run{ID: uuid.New(), ProjectID: &pid, Kind: "backup", Status: "success", StartedAt: time.Now()})
	e.svc.Tick(context.Background())
	if len(e.repo.snaps) != n {
		t.Fatal("project backed up twice within its schedule")
	}
}

func TestRetentionDeletesOldObjectsPerProject(t *testing.T) {
	e := newEnv(t, true, "postgres")
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	e.svc.now = func() time.Time { return now }
	pid := e.proj.ID
	old := &Snapshot{ID: uuid.New(), ProjectID: &pid, ObjectKey: "projects/x/database/old.enc", CreatedAt: now.AddDate(0, 0, -20)}
	fresh := &Snapshot{ID: uuid.New(), ProjectID: &pid, ObjectKey: "projects/x/database/fresh.enc", CreatedAt: now.AddDate(0, 0, -2)}
	e.repo.snaps = []*Snapshot{old, fresh}
	e.store.objects[old.ObjectKey], e.store.objects[fresh.ObjectKey] = []byte("o"), []byte("f")
	e.svc.retain(context.Background(), &pid, 14)
	if _, ok := e.store.objects[old.ObjectKey]; ok {
		t.Fatal("old object kept")
	}
	if _, ok := e.store.objects[fresh.ObjectKey]; !ok {
		t.Fatal("fresh object deleted")
	}
	if len(e.repo.snaps) != 1 || e.repo.snaps[0].ID != fresh.ID {
		t.Fatalf("snapshots: %+v", e.repo.snaps)
	}
}

func TestSettingsValidationAndDefaults(t *testing.T) {
	e := newEnv(t, true, "postgres")
	ctx := context.Background()
	v, err := e.svc.Get(ctx, e.proj.ID)
	if err != nil || !v.Enabled || v.Schedule != "daily" || v.RetentionDays != 14 || !v.Include.Databases || v.Include.Volumes || v.NextRun == nil {
		t.Fatalf("default view for a project with databases: %+v %v", v, err)
	}
	noDB := newEnv(t, true)
	if v, _ := noDB.svc.Get(ctx, noDB.proj.ID); v.Enabled {
		t.Fatal("project without databases must not be enabled by default")
	}
	bad := []Patch{
		{Schedule: strp("monthly")},
		{RetentionDays: ptr(0)},
		{RetentionDays: ptr(31)},
	}
	for i, p := range bad {
		var inv *InvalidError
		if _, err := e.svc.Update(ctx, e.proj.ID, p); !errors.As(err, &inv) {
			t.Errorf("patch %d: want InvalidError, got %v", i, err)
		}
	}
	v, err = e.svc.Update(ctx, e.proj.ID, Patch{Schedule: strp("6h"), RetentionDays: ptr(30), IncludeVolumes: boolp(true), Enabled: boolp(false)})
	if err != nil || v.Enabled || v.Schedule != "6h" || v.RetentionDays != 30 || !v.Include.Volumes || !v.Include.Databases {
		t.Fatalf("update: %+v %v", v, err)
	}
	if v.NextRun != nil {
		t.Fatal("disabled project must have next_run null")
	}
}

func ptr(i int) *int        { return &i }
func boolp(b bool) *bool    { return &b }
func strp(s string) *string { return &s }

// ── restore ─────────────────────────────────────────────────────────────────

// seed backs the project up and returns the database and volume snapshots.
func seed(t *testing.T, e *env, vol bool) (db, volume *Snapshot) {
	t.Helper()
	e.dock.streamFn = func(c Cmd) (io.ReadCloser, error) {
		if strings.Contains(strings.Join(c.Args, " "), "tar --numeric-owner") {
			return okStream("TARBALL"), nil
		}
		return okStream("DUMP-ROWS"), nil
	}
	run := e.runNow(t, "backup", Settings{Enabled: true, IncludeDatabases: len(e.dbs.dbs) > 0, IncludeVolumes: vol, RetentionDays: 14})
	if run.Status != "success" {
		t.Fatalf("seed: %s %s", run.Status, run.Error)
	}
	for _, s := range e.repo.snaps {
		switch s.Kind {
		case "database":
			db = s
		case "volume":
			volume = s
		}
	}
	e.dock.calls, e.dock.stdin = nil, nil
	return
}

func TestRestoreDatabaseInPlaceIsAtomicAndStreamsPlaintext(t *testing.T) {
	e := newEnv(t, true, "postgres")
	db, _ := seed(t, e, false)
	e.repo.runs = nil
	pid, oid := e.proj.ID, e.proj.OrgID
	r := e.svc.newRun(&pid, &oid, "restore", "manual", nil)
	_ = e.repo.CreateRun(context.Background(), &r)
	e.svc.executeRestore(r, db, "")
	got := e.repo.run(r.ID)
	if got.Status != "success" {
		t.Fatalf("%s %s", got.Status, got.Error)
	}
	i := e.dock.find("pg_restore")
	if i < 0 {
		t.Fatal("pg_restore not called")
	}
	if a := strings.Join(e.dock.calls[i].Args, " "); !strings.Contains(a, "--single-transaction") || !strings.Contains(a, "--clean") || !strings.Contains(a, "-d db0") {
		t.Fatalf("in-place restore must be a single transaction on the original db: %s", a)
	}
	if string(e.dock.stdin[i]) != "DUMP-ROWS" {
		t.Fatalf("restore stdin %q", e.dock.stdin[i])
	}
	if e.dock.calls[i].Env[0] != "PGPASSWORD="+dbPassword {
		t.Fatal("password must be in env")
	}
}

func TestRestoreIntoTargetCreatesAndDropsOnFailure(t *testing.T) {
	e := newEnv(t, true, "postgres")
	db, _ := seed(t, e, false)
	e.dock.runFn = func(c Cmd) ([]byte, error) {
		if strings.Contains(strings.Join(c.Args, " "), "pg_restore") {
			return []byte("pg_restore: error: boom"), errors.New("exit status 1")
		}
		return nil, nil
	}
	e.repo.runs = nil
	pid, oid := e.proj.ID, e.proj.OrgID
	r := e.svc.newRun(&pid, &oid, "restore", "manual", nil)
	_ = e.repo.CreateRun(context.Background(), &r)
	e.svc.executeRestore(r, db, "restored_copy")
	got := e.repo.run(r.ID)
	if got.Status != "failed" || !strings.Contains(got.Error, "boom") {
		t.Fatalf("%s %s", got.Status, got.Error)
	}
	if e.dock.find(`CREATE DATABASE "restored_copy"`) < 0 {
		t.Fatal("target database not created")
	}
	if e.dock.find(`DROP DATABASE IF EXISTS "restored_copy"`) < 0 {
		t.Fatal("failed restore must drop the new database")
	}
	if e.dock.find("-d restored_copy") < 0 {
		t.Fatal("restore must go into the target")
	}
}

func TestRestoreRejectsTamperedSnapshotBeforeTouchingAnything(t *testing.T) {
	e := newEnv(t, true, "postgres")
	db, _ := seed(t, e, false)
	b := e.store.objects[db.ObjectKey]
	b[len(b)-1] ^= 0xff
	e.repo.runs = nil
	pid, oid := e.proj.ID, e.proj.OrgID
	r := e.svc.newRun(&pid, &oid, "restore", "manual", nil)
	_ = e.repo.CreateRun(context.Background(), &r)
	e.svc.executeRestore(r, db, "")
	got := e.repo.run(r.ID)
	if got.Status != "failed" || !strings.Contains(got.Error, "nothing was restored") {
		t.Fatalf("%s %s", got.Status, got.Error)
	}
	if e.dock.find("pg_restore") >= 0 {
		t.Fatal("restore ran on a tampered snapshot")
	}
}

func TestStartRestoreValidation(t *testing.T) {
	e := newEnv(t, true, "postgres", "redis")
	seed(t, e, false)
	ctx := context.Background()
	var pgSnap, redisSnap *Snapshot
	for _, s := range e.repo.snaps {
		if s.Kind == "database" && s.Engine == "postgres" {
			pgSnap = s
		}
		if s.Kind == "database" && s.Engine == "redis" {
			redisSnap = s
		}
	}
	if pgSnap == nil || redisSnap == nil {
		t.Fatal("seed missing snapshots")
	}
	var inv *InvalidError
	if _, err := e.svc.StartRestore(ctx, e.proj.ID, redisSnap.ID, "", nil); !errors.As(err, &inv) || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("redis restore: %v", err)
	}
	if _, err := e.svc.StartRestore(ctx, e.proj.ID, pgSnap.ID, "bad name;", nil); !errors.As(err, &inv) {
		t.Fatalf("bad target: %v", err)
	}
	if _, err := e.svc.StartRestore(ctx, e.proj.ID, uuid.New(), "", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown snapshot: %v", err)
	}
	other := uuid.New()
	e.proj.ID = other // a snapshot of another project is invisible
	if _, err := e.svc.StartRestore(ctx, other, pgSnap.ID, "", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign snapshot: %v", err)
	}
	for _, s := range e.repo.snaps {
		if s.Kind == "manifest" {
			e.proj.ID = *s.ProjectID
			if _, err := e.svc.StartRestore(ctx, *s.ProjectID, s.ID, "", nil); !errors.As(err, &inv) {
				t.Fatalf("manifest restore: %v", err)
			}
		}
	}
}

func volSnapshot(t *testing.T) (*env, *Snapshot) {
	e := newEnv(t, true)
	_, vol := seed(t, e, true)
	if vol == nil {
		t.Fatal("no volume snapshot")
	}
	return e, vol
}

func restoreVol(t *testing.T, e *env, s *Snapshot) *Run {
	e.repo.runs = nil
	pid, oid := e.proj.ID, e.proj.OrgID
	r := e.svc.newRun(&pid, &oid, "restore", "manual", nil)
	_ = e.repo.CreateRun(context.Background(), &r)
	e.svc.executeRestore(r, s, "")
	return e.repo.run(r.ID)
}

func TestVolumeRestoreStopsSwapsAndRestarts(t *testing.T) {
	e, vol := volSnapshot(t)
	e.dock.runFn = func(c Cmd) ([]byte, error) {
		if strings.HasPrefix(strings.Join(c.Args, " "), "ps --filter") {
			return []byte("capsule-app-abc\n"), nil
		}
		return nil, nil
	}
	got := restoreVol(t, e, vol)
	if got.Status != "success" {
		t.Fatalf("%s %s", got.Status, got.Error)
	}
	j := e.dock.joined()
	idx := func(sub string) int {
		for i, c := range j {
			if strings.Contains(c, sub) {
				return i
			}
		}
		return -1
	}
	extract, stop, swap, start := idx("tar --numeric-owner -xzpf"), idx("stop capsule-app-abc"), idx("mv {} /stage/old/"), idx("start capsule-app-abc")
	if !(extract >= 0 && extract < stop && stop < swap && swap < start) {
		t.Fatalf("order must be extract(staging) < stop < swap < start: %d %d %d %d\n%s", extract, stop, swap, start, strings.Join(j, "\n"))
	}
	if string(e.dock.stdin[extract]) != "TARBALL" {
		t.Fatalf("extract got %q", e.dock.stdin[extract])
	}
	if idx("volume rm -f capsule-restore-") < 0 {
		t.Fatal("staging volume not cleaned")
	}
	if idx("rm -rf") >= 0 {
		t.Fatal("rollback ran on success")
	}
}

func TestVolumeRestoreRollsBackWhenSwapFails(t *testing.T) {
	e, vol := volSnapshot(t)
	e.dock.runFn = func(c Cmd) ([]byte, error) {
		a := strings.Join(c.Args, " ")
		switch {
		case strings.HasPrefix(a, "ps --filter"):
			return []byte("capsule-app-abc\n"), nil
		case strings.Contains(a, "mv {} /stage/old/"):
			return []byte("mv: no space left"), errors.New("exit status 1")
		}
		return nil, nil
	}
	got := restoreVol(t, e, vol)
	if got.Status != "failed" || !strings.Contains(got.Error, "previous data restored") {
		t.Fatalf("%s %s", got.Status, got.Error)
	}
	rb, start, stop := e.dock.find("rm -rf"), e.dock.find("start capsule-app-abc"), e.dock.find("stop capsule-app-abc")
	if rb < 0 || start < 0 || stop < 0 || !(stop < rb && rb < start) {
		t.Fatalf("want stop < rollback < restart: %d %d %d\n%s", stop, rb, start, strings.Join(e.dock.joined(), "\n"))
	}
	if e.dock.find("volume rm -f capsule-restore-") < 0 {
		t.Fatal("staging volume should be removed after a successful rollback")
	}
}

func TestVolumeRestoreKeepsStagingWhenRollbackAlsoFails(t *testing.T) {
	e, vol := volSnapshot(t)
	e.dock.runFn = func(c Cmd) ([]byte, error) {
		a := strings.Join(c.Args, " ")
		if strings.Contains(a, "mv {} /stage/old/") || strings.Contains(a, "rm -rf") {
			return nil, errors.New("exit status 1")
		}
		return nil, nil
	}
	got := restoreVol(t, e, vol)
	if got.Status != "failed" || !strings.Contains(got.Error, "ROLLBACK FAILED") {
		t.Fatalf("%s %s", got.Status, got.Error)
	}
	if e.dock.find("volume rm -f capsule-restore-") >= 0 {
		t.Fatal("staging volume holds the previous data and must be kept")
	}
}

func TestVolumeRestoreExtractionFailureNeverTouchesLiveData(t *testing.T) {
	e, vol := volSnapshot(t)
	e.dock.runFn = func(c Cmd) ([]byte, error) {
		a := strings.Join(c.Args, " ")
		if strings.Contains(a, "tar --numeric-owner -xzpf") {
			return []byte("tar: corrupt"), errors.New("exit status 2")
		}
		return nil, nil
	}
	got := restoreVol(t, e, vol)
	if got.Status != "failed" || !strings.Contains(got.Error, "live data untouched") {
		t.Fatalf("%s %s", got.Status, got.Error)
	}
	if e.dock.find("stop ") >= 0 || e.dock.find("mv {}") >= 0 {
		t.Fatal("containers were stopped or data moved although extraction failed")
	}
}

// ── verify & platform ───────────────────────────────────────────────────────

func TestVerifyChecksTheLatestBackupsWithoutTouchingData(t *testing.T) {
	e := newEnv(t, true, "postgres")
	db, _ := seed(t, e, false)
	run := e.runNow(t, "verify", Settings{})
	if run.Status != "success" {
		t.Fatalf("%s %s", run.Status, run.Error)
	}
	i := e.dock.find("pg_restore --list")
	if i < 0 || string(e.dock.stdin[i]) != "DUMP-ROWS" {
		t.Fatalf("postgres verify must run pg_restore --list on the dump (call %d)", i)
	}
	for _, c := range e.dock.joined() {
		if strings.Contains(c, "--clean") || strings.Contains(c, "DROP") || strings.Contains(c, "CREATE DATABASE") {
			t.Fatalf("verify touched data: %s", c)
		}
	}
	// tamper: verify must fail
	b := e.store.objects[db.ObjectKey]
	b[len(b)/2] ^= 0x55
	run = e.runNow(t, "verify", Settings{})
	if run.Status != "failed" || !strings.Contains(run.Error, "database") {
		t.Fatalf("tampered backup verified: %s %q", run.Status, run.Error)
	}
	// checksum mismatch with an intact object
	e2 := newEnv(t, true, "postgres")
	seed(t, e2, false)
	for _, s := range e2.repo.snaps {
		s.Checksum = strings.Repeat("0", 64)
	}
	if run := e2.runNow(t, "verify", Settings{}); run.Status != "failed" || !strings.Contains(run.Error, "checksum mismatch") {
		t.Fatalf("%s %q", run.Status, run.Error)
	}
	// nothing to verify
	e3 := newEnv(t, true)
	if run := e3.runNow(t, "verify", Settings{}); run.Status != "failed" || !strings.Contains(run.Error, "no backups") {
		t.Fatalf("%s %q", run.Status, run.Error)
	}
}

func TestPlatformBackupFilesAndInventory(t *testing.T) {
	e := newEnv(t, true)
	e.svc.cfg.PlatformDir, e.svc.cfg.DockerConfigDir = "/opt/capsule", "/etc/docker"
	e.dock.streamFn = func(Cmd) (io.ReadCloser, error) { return okStream("TAR-WITH-DOT-ENV"), nil }
	e.dock.runFn = func(c Cmd) ([]byte, error) {
		a := strings.Join(c.Args, " ")
		switch {
		case strings.HasPrefix(a, "volume ls"):
			return []byte("capsule-data-a\ncapsule-redis-data\n"), nil
		case strings.HasPrefix(a, "ps -a -q"):
			return []byte("abc123\ndef456\n"), nil
		case strings.HasPrefix(a, "ps -a --format"):
			return []byte("capsule-backend\timg\tUp 2 days\t0.0.0.0:8080->8080/tcp\n"), nil
		case strings.HasPrefix(a, "inspect abc123"):
			return []byte(`[{"Name":"/capsule-backend","Image":"sha256:1","State":{"Status":"running"},"Config":{"Image":"capsule/server:latest","Env":["CAPSULE_SECRET_KEY=hunter2","REDIS_PASSWORD=pw"]},"HostConfig":{"RestartPolicy":{"Name":"always"}},"Mounts":[{"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock"}],"NetworkSettings":{"Networks":{"capsule-net":{}},"Ports":{}}},
			{"Name":"/capsule-redis","Image":"sha256:2","State":{"Status":"running"},"Config":{"Image":"redis:7-alpine","Env":["X=1"]},"HostConfig":{"RestartPolicy":{"Name":"always"}},"Mounts":[],"NetworkSettings":{"Networks":{},"Ports":{}}}]`), nil
		}
		return nil, nil
	}
	run := e.svc.newRun(nil, nil, "backup", "manual", nil)
	_ = e.repo.CreateRun(context.Background(), &run)
	e.svc.execute(run, Settings{})
	got := e.repo.run(run.ID)
	if got.Status != "success" {
		t.Fatalf("%s %s", got.Status, got.Error)
	}
	var files, inv *Snapshot
	for _, s := range e.repo.snaps {
		if s.Kind != "platform" || s.ProjectID != nil {
			t.Fatalf("unexpected snapshot %+v", s)
		}
		if s.Source == "files" {
			files = s
		} else {
			inv = s
		}
	}
	if files == nil || inv == nil || !strings.HasPrefix(files.ObjectKey, "platform/") || !strings.HasSuffix(files.ObjectKey, ".files.tar.gz.enc") {
		t.Fatalf("platform snapshots: %+v %+v", files, inv)
	}
	if bytes.Contains(e.store.objects[files.ObjectKey], []byte("DOT-ENV")) {
		t.Fatal(".env tarball stored in the clear")
	}
	if string(e.plain(t, files.ObjectKey)) != "TAR-WITH-DOT-ENV" {
		t.Fatal("files round trip")
	}
	args := strings.Join(e.dock.calls[e.dock.find("--rm")].Args, " ")
	for _, want := range []string{"--network none", "--read-only", "/opt/capsule:/host/capsule:ro", "/etc/docker:/host/docker:ro", ".env", "certs", "daemon.json"} {
		if !strings.Contains(args, want) {
			t.Errorf("helper misses %q", want)
		}
	}
	if strings.Contains(args, "docker.sock") {
		t.Error("helper must not get the docker socket")
	}
	raw := e.plain(t, inv.ObjectKey)
	for _, secret := range []string{"hunter2", "REDIS_PASSWORD=pw"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("inventory leaks %q", secret)
		}
	}
	var iv Inventory
	if err := json.Unmarshal(raw, &iv); err != nil {
		t.Fatal(err)
	}
	if iv.Schema != 1 || len(iv.Containers) != 2 || len(iv.Volumes) != 2 || len(iv.PS) != 1 ||
		strings.Join(iv.Containers[0].EnvNames, ",") != "CAPSULE_SECRET_KEY,REDIS_PASSWORD" || iv.Containers[0].RestartPolicy != "always" {
		t.Fatalf("inventory: %+v", iv)
	}
	// verify the platform backup too
	vr := e.svc.newRun(nil, nil, "verify", "manual", nil)
	e.repo.runs = nil
	_ = e.repo.CreateRun(context.Background(), &vr)
	e.svc.execute(vr, Settings{})
	if r := e.repo.run(vr.ID); r.Status != "success" {
		t.Fatalf("platform verify: %s %s", r.Status, r.Error)
	}
}

func TestPanicInJobDoesNotLeaveRunRunning(t *testing.T) {
	e := newEnv(t, true, "postgres")
	e.dock.streamFn = func(Cmd) (io.ReadCloser, error) { panic("boom") }
	run := e.runNow(t, "backup", Settings{Enabled: true, IncludeDatabases: true, RetentionDays: 14})
	if run.Status != "failed" || !strings.Contains(run.Error, "internal error") {
		t.Fatalf("%s %q", run.Status, run.Error)
	}
	// the global slot was released
	select {
	case e.svc.sem <- struct{}{}:
		<-e.svc.sem
	default:
		t.Fatal("concurrency slot leaked")
	}
}

func TestPlatformRetentionNeverDeletesObjects(t *testing.T) {
	e := newEnv(t, true)
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	e.svc.now = func() time.Time { return now }
	old := &Snapshot{ID: uuid.New(), ObjectKey: "platform/old.enc", Kind: "platform", CreatedAt: now.AddDate(0, 0, -40)}
	recent := &Snapshot{ID: uuid.New(), ObjectKey: "platform/recent.enc", Kind: "platform", CreatedAt: now.AddDate(0, 0, -10)}
	e.repo.snaps = []*Snapshot{old, recent}
	e.store.objects[old.ObjectKey], e.store.objects[recent.ObjectKey] = []byte("a"), []byte("b")
	e.svc.retainPlatform(context.Background())
	if len(e.store.deleted) != 0 {
		t.Fatalf("platform/ objects must only be removed by the bucket lifecycle, deleted %v", e.store.deleted)
	}
	if len(e.repo.snaps) != 1 || e.repo.snaps[0].ID != recent.ID {
		t.Fatalf("only the lifecycle-expired snapshot row should be forgotten: %+v", e.repo.snaps)
	}
}
