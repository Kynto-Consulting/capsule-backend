package security

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

// Fake secret values. They are assembled at run time so that no file of the repository contains
// a string a secret scanner would flag. testdata/sarif/gitleaks.sarif keeps @@SECRET_n@@ markers
// where gitleaks wrote the values it found.
var fakeSecrets = map[string]string{
	"@@SECRET_1@@": "sk_" + "live_" + "FixtureValue0123456789ab",
	"@@SECRET_2@@": "AK" + "IA" + "FIXTURE0000TEST7",
	"@@SECRET_3@@": "gh" + "p_" + "FixtureValue0123456789abcdefghijklmno",
}

func fixtureBytes(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "sarif", name))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for ph, v := range fakeSecrets {
		s = strings.ReplaceAll(s, ph, v)
	}
	return s
}

func gzipB64(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func testParser() *Parser { return &Parser{Key: []byte("unit-test-fingerprint-key")} }

// ---- fake Git core (security.Forge) ---------------------------------------------------------

type fakeForge struct {
	mu         sync.Mutex
	enabled    bool
	repo       gitcore.Repository
	pulls      []gitcore.Pull
	files      map[string]bool // paths that exist on the default branch
	checks     []gitcore.CheckInput
	checkSHAs  []string
	dispatched []string
	dispatchEr error
	topics     map[string]bool
	withTopics bool
}

func newFakeForge() *fakeForge {
	return &fakeForge{enabled: true, repo: gitcore.Repository{DefaultBranch: "main"}, files: map[string]bool{}, topics: map[string]bool{}}
}

func (f *fakeForge) Enabled() bool { return f.enabled }
func (f *fakeForge) GetRepo(context.Context, gitcore.RepoRef) (*gitcore.Repository, error) {
	r := f.repo
	return &r, nil
}
func (f *fakeForge) ListPulls(_ context.Context, _ gitcore.RepoRef, q gitcore.PullQuery, _ gitcore.Page) (gitcore.List[gitcore.Pull], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return gitcore.List[gitcore.Pull]{Items: append([]gitcore.Pull(nil), f.pulls...)}, nil
}
func (f *fakeForge) GetFile(_ context.Context, _ gitcore.RepoRef, _, path string) (*gitcore.Blob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.files[path] {
		return &gitcore.Blob{Path: path}, nil
	}
	return nil, &gitcore.Error{Code: gitcore.CodeNotFound, Message: "no file"}
}
func (f *fakeForge) SetCheck(_ context.Context, _ gitcore.RepoRef, sha string, in gitcore.CheckInput) (*gitcore.Check, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks = append(f.checks, in)
	f.checkSHAs = append(f.checkSHAs, sha)
	return &gitcore.Check{Context: in.Context, State: in.State}, nil
}
func (f *fakeForge) DispatchWorkflow(_ context.Context, _ gitcore.RepoRef, workflow, ref string, _ map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dispatchEr != nil {
		return f.dispatchEr
	}
	f.dispatched = append(f.dispatched, workflow+"@"+ref)
	return nil
}
func (f *fakeForge) lastCheck() gitcore.CheckInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.checks) == 0 {
		return gitcore.CheckInput{}
	}
	return f.checks[len(f.checks)-1]
}

// topicForge adds the optional TopicSetter.
type topicForge struct{ *fakeForge }

func (f topicForge) SetRepoTopic(_ context.Context, _ gitcore.RepoRef, topic string, present bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.topics[topic] = present
	return nil
}

// ---- capturing publisher --------------------------------------------------------------------

type capPublisher struct {
	mu     sync.Mutex
	events []gitevents.Event
}

func (p *capPublisher) Publish(_ context.Context, e gitevents.Event) error {
	if err := gitevents.CheckNoSecrets(e.Data); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, e)
	return nil
}

func (p *capPublisher) named(name string) []gitevents.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []gitevents.Event
	for _, e := range p.events {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out
}

// ---- service rig ----------------------------------------------------------------------------

type rig struct {
	t     *testing.T
	svc   *Service
	store *MemStore
	forge *fakeForge
	pub   *capPublisher
	tgt   Target
	clock *time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()
	st := NewMemStore()
	tgt := Target{ProjectID: uuid.New(), OrgID: uuid.New(), OrgSlug: "acme", ProjectSlug: "app"}
	st.AddProject(tgt)
	forge := newFakeForge()
	pub := &capPublisher{}
	svc := New(st, forge, Config{FingerprintKey: "unit-test-fingerprint-key", UploadsPerMinute: 1000}, nil)
	svc.SetPublisher(pub)
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return now })
	r := &rig{t: t, svc: svc, store: st, forge: forge, pub: pub, tgt: tgt, clock: &now}
	svc.SetClock(func() time.Time { return *r.clock })
	return r
}

func (r *rig) advance(d time.Duration) { *r.clock = r.clock.Add(d) }

var (
	adminActor  = Actor{UserID: uuid.MustParse("00000000-0000-0000-0000-0000000000a1"), Login: "ada", Admin: true}
	triageActor = Actor{UserID: uuid.MustParse("00000000-0000-0000-0000-0000000000b2"), Login: "bob"}
)

const (
	shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	shaC = "cccccccccccccccccccccccccccccccccccccccc"
)

// upload sends a SARIF and runs the worker once.
func (r *rig) upload(sha, ref, sarif string, a Actor) *Upload {
	r.t.Helper()
	u, err := r.svc.Upload(context.Background(), r.tgt, a, UploadInput{CommitSHA: sha, Ref: ref, Sarif: sarif})
	if err != nil {
		r.t.Fatalf("upload: %v", err)
	}
	r.advance(time.Second)
	if _, err := r.svc.ProcessPending(context.Background(), 50); err != nil {
		r.t.Fatalf("process: %v", err)
	}
	got, err := r.svc.UploadStatus(context.Background(), r.tgt.ProjectID, u.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	if got.Status != UploadComplete {
		r.t.Fatalf("upload %s is %s: %s", u.ID, got.Status, got.Error)
	}
	return got
}

func (r *rig) alerts(q AlertQuery) []Alert {
	r.t.Helper()
	q.IncludeSecrets = true
	q.Limit = 100
	items, _, err := r.svc.ListAlerts(context.Background(), r.tgt.ProjectID, q)
	if err != nil {
		r.t.Fatal(err)
	}
	return items
}

// miniSarif builds a SARIF with one run and the given results (rule, path, snippet, level).
type mini struct{ rule, path, snippet, level string }

func miniSarif(tool string, rs ...mini) string {
	type loc = map[string]any
	var results []any
	for _, m := range rs {
		results = append(results, map[string]any{
			"ruleId": m.rule, "level": m.level, "message": map[string]any{"text": "problem " + m.rule},
			"locations": []any{loc{"physicalLocation": loc{
				"artifactLocation": loc{"uri": m.path},
				"region":           loc{"startLine": 3, "snippet": loc{"text": m.snippet}},
			}}},
		})
	}
	b, _ := json.Marshal(map[string]any{
		"version": "2.1.0",
		"runs":    []any{map[string]any{"tool": map[string]any{"driver": map[string]any{"name": tool}}, "results": results}},
	})
	return string(b)
}
