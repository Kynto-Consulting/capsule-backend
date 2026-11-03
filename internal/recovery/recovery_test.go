package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/backup"
)

const testSecret = "unit-test-platform-secret-0123456789"

var t0 = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

// put encrypts data with the real backup envelope into the store and returns its SnapshotRef.
func put(t *testing.T, st backup.Store, key string, data []byte, kind, source string, pid *uuid.UUID, at time.Time) SnapshotRef {
	t.Helper()
	dek, _ := backup.NewDEK()
	wrapped, err := backup.WrapDEK(dek, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	var enc bytes.Buffer
	w, _ := backup.NewEncryptWriter(&enc, dek)
	_, _ = w.Write(data)
	_ = w.Close()
	if _, err := st.Upload(context.Background(), key, map[string]string{"capsule-dek": wrapped}, &enc); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return SnapshotRef{ID: uuid.New(), ProjectID: pid, Kind: kind, Source: source, ObjectKey: key,
		Checksum: hex.EncodeToString(sum[:]), CreatedAt: at, Size: int64(len(data))}
}

func manifestFor(pid, run uuid.UUID, dbID uuid.UUID) []byte {
	m := backup.Manifest{Schema: 1, GeneratedAt: t0, RunID: run,
		Project:    backup.ManifestProject{ID: pid, Slug: "shop"},
		Deployment: &backup.ManifestDeploy{Version: "v1", SourceKey: "deployments/x.tar.gz"},
		Volumes:    []backup.ManifestVolume{{Name: "capsule-data-" + pid.String(), MountPoint: "/data"}},
		Databases:  []backup.ManifestDatabase{{ID: dbID, Name: "main", Engine: "postgres"}}}
	b, _ := json.Marshal(m)
	return b
}

// ── plan: determinism and table of rules ──────────────────────────────────────

func fixtureCatalog() (Catalog, uuid.UUID) {
	pid := uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	dbID := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	mid := uuid.MustParse("00000000-0000-4000-8000-0000000000e1")
	ref := func(n byte, kind, source, sid string, age time.Duration) SnapshotRef {
		id := uuid.UUID{15: n}
		return SnapshotRef{ID: id, ProjectID: &pid, Kind: kind, Source: source, SourceID: sid, ObjectKey: "k/" + id.String(), Size: 40 << 20, Checksum: "ab", CreatedAt: t0.Add(-age)}
	}
	return Catalog{Now: t0,
		Projects: []ProjectEntry{{ID: pid, Slug: "shop", Snapshots: []SnapshotRef{
			ref(1, "database", "main", dbID.String(), 30*time.Hour), ref(2, "database", "main", dbID.String(), 6*time.Hour),
			ref(3, "volume", "capsule-data-"+pid.String(), "", 6*time.Hour), ref(4, "manifest", "manifest", "", 6*time.Hour)},
			Manifest: &ManifestSummary{SnapshotID: uuid.UUID{15: 4}, Databases: []string{dbID.String()}, Volumes: []string{"capsule-data-" + pid.String()}, HasSource: true}}},
		Platform:     []SnapshotRef{{ID: mid, Kind: "platform", Source: "files", ObjectKey: "platform/x", Size: 1 << 20, CreatedAt: t0.Add(-3 * time.Hour)}},
		ForgejoDumps: []DumpRef{{Key: "forgejo/a.tar.gz.enc", LastModified: t0.Add(-5 * time.Hour), Sha256: strings.Repeat("a", 64), Size: 100 << 20}},
	}, pid
}

func TestPlanDeterministic(t *testing.T) {
	cat, _ := fixtureCatalog()
	req := Request{Mode: ModePlan, All: true}
	first, err := BuildPlan(req, cat)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		// shuffle the input order: the plan must not change
		c2 := cat
		c2.Projects = []ProjectEntry{cat.Projects[0]}
		sn := append([]SnapshotRef(nil), cat.Projects[0].Snapshots...)
		sn[0], sn[len(sn)-1] = sn[len(sn)-1], sn[0]
		c2.Projects[0].Snapshots = sn
		p, err := BuildPlan(req, c2)
		if err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(first)
		b, _ := json.Marshal(p)
		if !bytes.Equal(a, b) || p.PlanID != first.PlanID {
			t.Fatalf("plan differs between runs:\n%s\n%s", a, b)
		}
	}
	var order []string
	for _, s := range first.Steps {
		order = append(order, s.Phase)
	}
	want := []string{"F0", "F1", "F2", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("phase order %v, want %v", order, want)
	}
}

func TestPlanRules(t *testing.T) {
	cat, pid := fixtureCatalog()
	older := t0.Add(-10 * time.Hour)
	snap1 := uuid.UUID{15: 1}
	cases := []struct {
		name      string
		req       Request
		mutate    func(c *Catalog)
		wantRisks []string // codes, sorted by severity then code
		check     func(t *testing.T, p Plan)
	}{
		{name: "latest snapshot chosen", req: Request{Mode: ModePlan, ProjectID: &pid}, check: func(t *testing.T, p Plan) {
			if !strings.HasSuffix(findStep(p, "f4-db-").ID, uuid.UUID{15: 2}.String()) {
				t.Fatalf("expected newest db snapshot, got %s", findStep(p, "f4-db-").ID)
			}
		}},
		{name: "point in time picks the older one", req: Request{Mode: ModePlan, ProjectID: &pid, At: &older}, wantRisks: []string{"NO_VOLUME_BACKUP"}, check: func(t *testing.T, p Plan) {
			if !strings.HasSuffix(findStep(p, "f4-db-").ID, snap1.String()) {
				t.Fatalf("expected older db snapshot")
			}
		}},
		{name: "pinned snapshot", req: Request{Mode: ModePlan, ProjectID: &pid, SnapshotID: &snap1}, check: func(t *testing.T, p Plan) {
			if !strings.HasSuffix(findStep(p, "f4-db-").ID, snap1.String()) {
				t.Fatalf("pin ignored")
			}
		}},
		{name: "no volume backup is a warning", req: Request{Mode: ModePlan, ProjectID: &pid},
			mutate: func(c *Catalog) { c.Projects[0].Snapshots = dropKind(c.Projects[0].Snapshots, "volume") }, wantRisks: []string{"NO_VOLUME_BACKUP"}},
		{name: "missing database backup blocks", req: Request{Mode: ModePlan, ProjectID: &pid},
			mutate: func(c *Catalog) { c.Projects[0].Snapshots = dropKind(c.Projects[0].Snapshots, "database") }, wantRisks: []string{"NO_DB_BACKUP"},
			check: func(t *testing.T, p Plan) {
				if p.Ready {
					t.Fatal("plan must not be ready")
				}
			}},
		{name: "rejected manifest excludes the project", req: Request{Mode: ModePlan, All: true, Scopes: []Scope{ScopeDatabases, ScopeProjects}},
			mutate:    func(c *Catalog) { c.Projects[0].Manifest, c.Projects[0].ManifestErr = nil, "authentication failed" },
			wantRisks: []string{"MANIFEST_INVALID"}, check: func(t *testing.T, p Plan) {
				if findStep(p, "f4-db-").ID != "" {
					t.Fatal("project steps must be excluded")
				}
			}},
		{name: "no dump", req: Request{Mode: ModePlan, All: true, Scopes: []Scope{ScopeGit}},
			mutate: func(c *Catalog) { c.ForgejoDumps = nil }, wantRisks: []string{"NO_FORGEJO_DUMP"}},
		{name: "dump without checksum blocks", req: Request{Mode: ModePlan, All: true, Scopes: []Scope{ScopeGit}},
			mutate: func(c *Catalog) { c.ForgejoDumps[0].Sha256 = "" }, wantRisks: []string{"DUMP_NO_CHECKSUM"}},
		{name: "stale dump warns", req: Request{Mode: ModePlan, All: true, Scopes: []Scope{ScopeGit}},
			mutate: func(c *Catalog) { c.ForgejoDumps[0].LastModified = t0.Add(-30 * time.Hour) }, wantRisks: []string{"STALE_FORGEJO_DUMP"}},
		{name: "no platform backup blocks core", req: Request{Mode: ModePlan, All: true, Scopes: []Scope{ScopeCore}},
			mutate: func(c *Catalog) { c.Platform = nil }, wantRisks: []string{"NO_PLATFORM_BACKUP"}},
		{name: "ephemeral drops nothing but forbids dns", req: Request{Mode: ModePlan, All: true, Target: TargetEphemeral, Scopes: []Scope{ScopeDNS}}, wantRisks: []string{"!invalid"}},
		{name: "snapshot with all is invalid", req: Request{Mode: ModePlan, All: true, SnapshotID: &snap1}, wantRisks: []string{"!invalid"}},
		{name: "unknown project", req: Request{Mode: ModePlan, ProjectID: ptr(uuid.New())}, wantRisks: []string{"!notfound"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cc, _ := fixtureCatalog()
			if c.mutate != nil {
				c.mutate(&cc)
			}
			p, err := BuildPlan(c.req, cc)
			if len(c.wantRisks) == 1 && strings.HasPrefix(c.wantRisks[0], "!") {
				want := map[string]error{"!invalid": ErrInvalid, "!notfound": ErrNotFound}[c.wantRisks[0]]
				if !errors.Is(err, want) {
					t.Fatalf("err = %v, want %v", err, want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, r := range p.Risks {
				got = append(got, r.Code)
			}
			if len(c.wantRisks) == 0 && len(got) > 0 {
				t.Fatalf("unexpected risks %v", got)
			}
			for _, w := range c.wantRisks {
				found := false
				for _, g := range got {
					found = found || g == w
				}
				if !found {
					t.Fatalf("risk %s not in %v", w, got)
				}
			}
			if c.check != nil {
				c.check(t, p)
			}
		})
	}
	_ = cat
}

func ptr[T any](v T) *T { return &v }

func dropKind(in []SnapshotRef, kind string) []SnapshotRef {
	var out []SnapshotRef
	for _, s := range in {
		if s.Kind != kind {
			out = append(out, s)
		}
	}
	return out
}

func findStep(p Plan, prefix string) Step {
	for _, s := range p.Steps {
		if strings.HasPrefix(s.ID, prefix) {
			return s
		}
	}
	return Step{}
}

// ── engine: idempotent steps and resume ───────────────────────────────────────

type countExec struct {
	checks, applies, verifies atomic.Int32
	done                      atomic.Bool
	failApply                 bool
}

func (c *countExec) Check(context.Context, Step, RunCtx) (bool, string, error) {
	c.checks.Add(1)
	return c.done.Load(), "present", nil
}
func (c *countExec) Apply(context.Context, Step, RunCtx) (string, error) {
	c.applies.Add(1)
	if c.failApply {
		return "", errors.New("boom")
	}
	c.done.Store(true)
	return "applied", nil
}
func (c *countExec) Verify(context.Context, Step, RunCtx) (string, error) {
	c.verifies.Add(1)
	return "", nil
}

func TestEngineRepeatedStepHasNoDoubleEffect(t *testing.T) {
	cat, pid := fixtureCatalog()
	plan, _ := BuildPlan(Request{Mode: ModeApply, ProjectID: &pid, Scopes: []Scope{ScopeDatabases}}, cat)
	ex := &countExec{}
	j := NewMemJournal()
	eng := &Engine{Journal: j, Execs: map[Kind]Exec{KindPreflight: ex, KindDatabase: ex, KindSmoke: ex, KindReport: ex}, Now: func() time.Time { return t0 }}
	for i := 0; i < 2; i++ { // the second run is a fresh run over the same destination
		run := &Run{ID: uuid.New(), Mode: ModeApply, Request: plan.Request, StartedAt: t0}
		if _, _, err := j.Begin(context.Background(), run); err != nil {
			t.Fatal(err)
		}
		ex.done.Store(i == 1) // destination already holds the data on the second pass
		before := ex.applies.Load()
		if err := eng.Execute(context.Background(), plan, run); err != nil {
			t.Fatal(err)
		}
		if run.Status != RunSuccess {
			t.Fatalf("status %s: %+v", run.Status, run.Steps)
		}
		if i == 1 && ex.applies.Load() != before {
			t.Fatalf("destination already restored but apply ran again")
		}
	}
}

func TestEngineResumeSkipsOkSteps(t *testing.T) {
	cat, pid := fixtureCatalog()
	plan, _ := BuildPlan(Request{Mode: ModeApply, ProjectID: &pid, Scopes: []Scope{ScopeDatabases}}, cat)
	good, bad := &countExec{}, &countExec{failApply: true}
	j := NewMemJournal()
	execs := map[Kind]Exec{KindPreflight: good, KindDatabase: bad, KindSmoke: good, KindReport: good}
	eng := &Engine{Journal: j, Execs: execs}
	run := &Run{ID: uuid.New(), Mode: ModeApply, Request: plan.Request, StartedAt: t0}
	_, _, _ = j.Begin(context.Background(), run)
	_ = eng.Execute(context.Background(), plan, run)
	if run.Status != RunFailed && run.Status != RunPartial {
		t.Fatalf("status %s", run.Status)
	}
	pre := good.applies.Load()
	bad.failApply = false
	execs[KindDatabase] = bad
	if err := eng.Execute(context.Background(), plan, run); err != nil { // --resume RUN_ID
		t.Fatal(err)
	}
	if run.Status != RunSuccess {
		t.Fatalf("resume status %s", run.Status)
	}
	if got := run.step("f0-preflight").Attempts; got != 1 {
		t.Fatalf("preflight re-ran on resume (attempts=%d)", got)
	}
	_ = pre
}

func TestOneActiveApply(t *testing.T) {
	j := NewMemJournal()
	a := &Run{ID: uuid.New(), Mode: ModeApply, Status: RunRunning}
	if _, _, err := j.Begin(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.Begin(context.Background(), &Run{ID: uuid.New(), Mode: ModeApply}); !errors.Is(err, ErrActive) {
		t.Fatalf("want ErrActive, got %v", err)
	}
	if _, _, err := j.Begin(context.Background(), &Run{ID: uuid.New(), Mode: ModeVerify}); err != nil {
		t.Fatalf("verify must not be blocked: %v", err)
	}
}

func TestIdempotencyKeyReturnsSameRun(t *testing.T) {
	j := NewMemJournal()
	u := uuid.New()
	r1 := &Run{ID: uuid.New(), Mode: ModeVerify, IdempotencyKey: "k", RequestedBy: &u}
	_, created, _ := j.Begin(context.Background(), r1)
	ex, created2, _ := j.Begin(context.Background(), &Run{ID: uuid.New(), Mode: ModeVerify, IdempotencyKey: "k", RequestedBy: &u})
	if !created || created2 || ex.ID != r1.ID {
		t.Fatal("same idempotency key must return the first run")
	}
}

func TestFileJournalRoundTrip(t *testing.T) {
	j := &FileJournal{Dir: t.TempDir()}
	r := &Run{ID: uuid.New(), Mode: ModeApply, Status: RunRunning, Steps: []StepState{{ID: "a", Status: StepOK}}}
	if _, _, err := j.Begin(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	got, err := j.Get(context.Background(), r.ID)
	if err != nil || got.Steps[0].Status != StepOK {
		t.Fatalf("%v %+v", err, got)
	}
	if _, _, err := j.Begin(context.Background(), &Run{ID: uuid.New(), Mode: ModeApply}); !errors.Is(err, ErrActive) {
		t.Fatalf("file journal must enforce one active apply: %v", err)
	}
}

// ── real envelope: restore, tamper, idempotence on a directory ────────────────

func TestDirRestorerIdempotentAndAtomic(t *testing.T) {
	st := &DirStore{Root: t.TempDir()}
	pid := uuid.New()
	data := bytes.Repeat([]byte("row,1\n"), 300000) // > 1 MiB: several GCM chunks
	sn := put(t, st, "projects/"+pid.String()+"/database/x.pgdump.enc", data, "database", "main", &pid, t0)
	v := &Verifier{Store: st, Secret: testSecret}
	r := &DirRestorer{V: v, Dir: t.TempDir()}
	ctx := context.Background()
	run := uuid.New()

	if done, _, err := r.Check(ctx, sn); err != nil || done {
		t.Fatalf("fresh destination must not be done: %v %v", done, err)
	}
	if _, err := r.Restore(ctx, sn, false, run); err != nil {
		t.Fatal(err)
	}
	if done, _, _ := r.Check(ctx, sn); !done {
		t.Fatal("after restore, check must report done (same checksum)")
	}
	if _, err := r.Verify(ctx, sn); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(r.dest(sn))
	if !bytes.Equal(got, data) {
		t.Fatal("restored bytes differ")
	}

	// different local content: needs --force-overwrite and keeps a pre-restore copy
	if err := os.WriteFile(r.dest(sn), []byte("local edits"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Restore(ctx, sn, false, run); !errors.Is(err, ErrNeedOverwrite) {
		t.Fatalf("want ErrNeedOverwrite, got %v", err)
	}
	if b, _ := os.ReadFile(r.dest(sn)); string(b) != "local edits" {
		t.Fatal("destination changed without force")
	}
	if _, err := r.Restore(ctx, sn, true, run); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(r.dest(sn) + ".pre-restore-" + run.String()); string(b) != "local edits" {
		t.Fatal("pre-restore copy not kept")
	}

	// corrupted object: nothing is restored, destination untouched, no temp left behind
	obj := st.file(sn.ObjectKey)
	raw, _ := os.ReadFile(obj)
	raw[len(raw)/2] ^= 0xff
	_ = os.WriteFile(obj, raw, 0o644)
	if _, err := r.Restore(ctx, sn, true, uuid.New()); err == nil {
		t.Fatal("tampered object must fail")
	}
	if b, _ := os.ReadFile(r.dest(sn)); !bytes.Equal(b, data) {
		t.Fatal("failed restore modified the destination")
	}
	ents, _ := os.ReadDir(filepath.Dir(r.dest(sn)))
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
}

func TestChecksumMismatchDetected(t *testing.T) {
	st := &DirStore{Root: t.TempDir()}
	pid := uuid.New()
	sn := put(t, st, "projects/"+pid.String()+"/volume/x.tar.gz.enc", []byte("hello"), "volume", "v", &pid, t0)
	sn.Checksum = strings.Repeat("0", 64) // catalog says something else (replaced object, replayed old backup)
	v := &Verifier{Store: st, Secret: testSecret}
	if _, _, err := v.Stream(context.Background(), sn, nil); !errors.Is(err, ErrChecksum) {
		t.Fatalf("want ErrChecksum, got %v", err)
	}
}

func TestManifestTamperingRejected(t *testing.T) {
	st := &DirStore{Root: t.TempDir()}
	v := &Verifier{Store: st, Secret: testSecret}
	pid, other, run, db := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	key := "projects/" + pid.String() + "/manifest/2026-11-02T07:00:03Z-" + run.String() + ".json.enc"
	good := put(t, st, key, manifestFor(pid, run, db), "manifest", "manifest", &pid, t0)
	ctx := context.Background()
	if _, err := v.Manifest(ctx, good); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}

	t.Run("flipped byte", func(t *testing.T) {
		obj := st.file(key)
		raw, _ := os.ReadFile(obj)
		orig := append([]byte(nil), raw...)
		raw[len(raw)-3] ^= 1
		_ = os.WriteFile(obj, raw, 0o644)
		defer os.WriteFile(obj, orig, 0o644)
		if _, err := v.Manifest(ctx, good); !errors.Is(err, ErrManifest) || !errors.Is(err, backup.ErrAuth) {
			t.Fatalf("want ErrManifest+ErrAuth, got %v", err)
		}
	})
	t.Run("encrypted by an attacker with another key", func(t *testing.T) {
		evil := &Verifier{Store: st, Secret: "attacker-secret-attacker-secret-1234"}
		_ = evil
		dek, _ := backup.NewDEK()
		wrapped, _ := backup.WrapDEK(dek, "attacker-secret-attacker-secret-1234")
		var enc bytes.Buffer
		w, _ := backup.NewEncryptWriter(&enc, dek)
		_, _ = w.Write(manifestFor(pid, run, db))
		_ = w.Close()
		k2 := "projects/" + pid.String() + "/manifest/2026-11-02T08:00:00Z-" + run.String() + ".json.enc"
		_, _ = st.Upload(ctx, k2, map[string]string{"capsule-dek": wrapped}, &enc)
		sn := good
		sn.ObjectKey, sn.Checksum = k2, ""
		if _, err := v.Manifest(ctx, sn); !errors.Is(err, ErrManifest) {
			t.Fatalf("manifest forged without the platform key must be rejected, got %v", err)
		}
	})
	t.Run("manifest of another project", func(t *testing.T) {
		k2 := "projects/" + pid.String() + "/manifest/2026-11-02T09:00:00Z-" + run.String() + ".json.enc"
		sn := put(t, st, k2, manifestFor(other, run, db), "manifest", "manifest", &pid, t0)
		if _, err := v.Manifest(ctx, sn); !errors.Is(err, ErrManifest) {
			t.Fatalf("swapped manifest must be rejected, got %v", err)
		}
	})
	t.Run("unknown schema", func(t *testing.T) {
		var m map[string]any
		_ = json.Unmarshal(manifestFor(pid, run, db), &m)
		m["schema"] = 2
		b, _ := json.Marshal(m)
		k2 := "projects/" + pid.String() + "/manifest/2026-11-02T10:00:00Z-" + run.String() + ".json.enc"
		sn := put(t, st, k2, b, "manifest", "manifest", &pid, t0)
		if _, err := v.Manifest(ctx, sn); !errors.Is(err, ErrManifest) || !strings.Contains(err.Error(), "schema") {
			t.Fatalf("want schema rejection, got %v", err)
		}
	})
	t.Run("replayed older manifest (checksum of the catalog differs)", func(t *testing.T) {
		old := put(t, st, "projects/"+pid.String()+"/manifest/2026-10-01T07:00:00Z-"+run.String()+".json.enc", manifestFor(pid, run, db), "manifest", "manifest", &pid, t0)
		sn := good
		sn.ObjectKey = old.ObjectKey
		sn.Checksum = strings.Repeat("1", 64)
		if _, err := v.Manifest(ctx, sn); !errors.Is(err, ErrManifest) || !errors.Is(err, ErrChecksum) {
			t.Fatalf("want checksum failure, got %v", err)
		}
	})
}

func TestCatalogRejectsTamperedNewestManifestWithoutFallback(t *testing.T) {
	st := &DirStore{Root: t.TempDir()}
	v := &Verifier{Store: st, Secret: testSecret}
	pid, run, db := uuid.New(), uuid.New(), uuid.New()
	older := put(t, st, "projects/"+pid.String()+"/manifest/2026-11-01T07:00:00Z-"+run.String()+".json.enc", manifestFor(pid, run, db), "manifest", "manifest", &pid, t0.Add(-24*time.Hour))
	newer := put(t, st, "projects/"+pid.String()+"/manifest/2026-11-02T07:00:00Z-"+run.String()+".json.enc", manifestFor(pid, run, db), "manifest", "manifest", &pid, t0)
	obj := st.file(newer.ObjectKey)
	raw, _ := os.ReadFile(obj)
	raw[20] ^= 0xff
	_ = os.WriteFile(obj, raw, 0o644)
	pe := ProjectEntry{ID: pid, Slug: "shop", Snapshots: []SnapshotRef{older, newer}}
	verifyNewestManifest(context.Background(), v, &pe)
	if pe.Manifest != nil || pe.ManifestErr == "" {
		t.Fatalf("tampered newest manifest must be rejected, with no fallback to the older one: %+v", pe)
	}
}

func TestBucketCatalogParsesKeys(t *testing.T) {
	pid, run := uuid.New(), uuid.New()
	ts := t0.Format(time.RFC3339)
	for _, c := range []struct {
		key, kind string
	}{
		{backup.ObjectKey(pid, "database", t0, run, "abcd1234.pgdump"), "database"},
		{backup.ObjectKey(pid, "volume", t0, run, "tar.gz"), "volume"},
		{backup.ObjectKey(pid, "manifest", t0, run, "json"), "manifest"},
		{backup.PlatformKey(t0, run, "files", "tar.gz"), "platform"},
	} {
		ref, ok := refFromKey(backup.ObjectInfo{Key: c.key, Size: 5})
		if !ok || ref.Kind != c.kind || !ref.CreatedAt.Equal(t0) {
			t.Fatalf("%s: %+v ok=%v (ts %s)", c.key, ref, ok, ts)
		}
	}
	if _, ok := refFromKey(backup.ObjectInfo{Key: "forgejo/x.tar.gz.enc"}); ok {
		t.Fatal("forgejo objects are not backup snapshots")
	}
}

func TestBucketCatalogEndToEndPlan(t *testing.T) {
	st := &DirStore{Root: t.TempDir()}
	v := &Verifier{Store: st, Secret: testSecret}
	pid, run, db := uuid.New(), uuid.New(), uuid.New()
	put(t, st, backup.ObjectKey(pid, "manifest", t0, run, "json"), manifestFor(pid, run, db), "manifest", "manifest", &pid, t0)
	put(t, st, backup.ObjectKey(pid, "database", t0, run, db.String()[:8]+".pgdump"), []byte("dump"), "database", "main", &pid, t0)
	cat, err := CatalogFromBucket(context.Background(), st, v, nil, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildPlan(Request{Mode: ModePlan, ProjectID: &pid}, cat)
	if err != nil {
		t.Fatal(err)
	}
	var codes []string
	for _, r := range p.Risks {
		codes = append(codes, r.Code)
	}
	if strings.Contains(strings.Join(codes, ","), "NO_DB_BACKUP") {
		t.Fatalf("db matched by 8-char prefix expected, risks %v", codes)
	}
	if !strings.Contains(strings.Join(codes, ","), "NO_CHECKSUM_CATALOG") {
		t.Fatalf("bucket catalog must warn about missing checksums: %v", codes)
	}
}

// ── scripts, preflight, report ────────────────────────────────────────────────

type fakeRunner struct {
	calls [][]string
	codes map[string]int
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, env []string) ([]byte, int, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return []byte("line1\nresult"), f.codes[args[len(args)-1]], nil
}

func TestScriptExecContract(t *testing.T) {
	fr := &fakeRunner{codes: map[string]int{"check": 10}}
	x := ScriptExec{Runner: fr, Dir: "d", Script: "git-restore.sh"}
	done, _, err := x.Check(context.Background(), Step{ID: "f3-git"}, RunCtx{RunID: uuid.New()})
	if err != nil || done {
		t.Fatalf("exit 10 means not done: %v %v", done, err)
	}
	fr.codes["check"] = 0
	if done, d, _ := x.Check(context.Background(), Step{ID: "f3-git"}, RunCtx{RunID: uuid.New()}); !done || d != "result" {
		t.Fatalf("exit 0 means done: %v %q", done, d)
	}
	fr.codes["apply"] = 3
	if _, err := x.Apply(context.Background(), Step{ID: "f3-git"}, RunCtx{RunID: uuid.New()}); err == nil {
		t.Fatal("non-zero apply must fail")
	}
}

func TestPreflightFailsWithoutKeyOrWithWrongKey(t *testing.T) {
	st := &DirStore{Root: t.TempDir()}
	pid := uuid.New()
	sn := put(t, st, "projects/"+pid.String()+"/manifest/x.enc", []byte("{}"), "manifest", "m", &pid, t0)
	if _, err := (PreflightExec{V: &Verifier{Store: st}}).Verify(context.Background(), Step{}, RunCtx{}); err == nil {
		t.Fatal("no key must fail")
	}
	if _, err := (PreflightExec{V: &Verifier{Store: st, Secret: "wrong-secret-wrong-secret-wrong-1"}, Probe: &sn}).Verify(context.Background(), Step{}, RunCtx{}); err == nil {
		t.Fatal("wrong key must fail the decrypt test")
	}
	if _, err := (PreflightExec{V: &Verifier{Store: st, Secret: testSecret}, Probe: &sn}).Verify(context.Background(), Step{}, RunCtx{}); err != nil {
		t.Fatal(err)
	}
}

func TestReportRedConditions(t *testing.T) {
	cat, pid := fixtureCatalog()
	plan, _ := BuildPlan(Request{Mode: ModeApply, ProjectID: &pid}, cat)
	start := t0
	end := t0.Add(5 * time.Hour)
	run := &Run{ID: uuid.New(), Mode: ModeApply, Status: RunSuccess, StartedAt: start, Steps: []StepState{{ID: "a", Phase: "F4", Status: StepOK, StartedAt: &start, FinishedAt: &end}}}
	rep := BuildReport(run, plan, end, time.Time{}, nil)
	if rep.Green || !strings.Contains(strings.Join(rep.Red, ";"), "RTO") {
		t.Fatalf("5 h run must be red for the RTO objective: %+v", rep.Red)
	}
	rep2 := BuildReport(run, plan, start.Add(time.Hour), start.Add(-40*24*time.Hour), nil)
	if rep2.Green || !strings.Contains(strings.Join(rep2.Red, ";"), "35 days") {
		t.Fatalf("old drill must be red: %+v", rep2.Red)
	}
	if rep.WorstRPOHrs != 30 && rep.WorstRPOHrs != 6 {
		t.Logf("worst rpo %d", rep.WorstRPOHrs)
	}
	if !strings.Contains(rep.Markdown(), "Red conditions") {
		t.Fatal("markdown must list red conditions")
	}
}
