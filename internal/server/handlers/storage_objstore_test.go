package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/objstore"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type objOrgs struct{ fakeOrgRepo }

func (objOrgs) GetByID(_ context.Context, id uuid.UUID) (*domain.Organization, error) {
	return &domain.Organization{ID: id, Slug: "acme"}, nil
}
func (o objOrgs) IsMember(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return o.role != "", nil
}

type objDBs struct {
	domain.DatabaseRepository
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.Database
}

func (f *objDBs) Create(_ context.Context, d *domain.Database) (*domain.Database, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := *d
	c.ID = uuid.New()
	f.rows[c.ID] = &c
	return &c, nil
}
func (f *objDBs) GetByID(_ context.Context, id uuid.UUID) (*domain.Database, error) {
	if d, ok := f.rows[id]; ok {
		return d, nil
	}
	return nil, domain.ErrNotFound
}
func (f *objDBs) ListByProject(_ context.Context, p uuid.UUID) ([]*domain.Database, error) {
	var out []*domain.Database
	for _, d := range f.rows {
		if d.ProjectID != nil && *d.ProjectID == p {
			out = append(out, d)
		}
	}
	return out, nil
}
func (f *objDBs) Delete(_ context.Context, id uuid.UUID) error { delete(f.rows, id); return nil }

type objEnv struct{ vars map[string]string }

func (e *objEnv) Upsert(_ context.Context, v *domain.EnvVar) (*domain.EnvVar, error) {
	e.vars[v.Key] = string(v.ValueEnc)
	return v, nil
}
func (e *objEnv) ListByProject(context.Context, uuid.UUID) ([]*domain.EnvVar, error) { return nil, nil }
func (e *objEnv) GetByKey(_ context.Context, _ uuid.UUID, k string) (*domain.EnvVar, error) {
	if v, ok := e.vars[k]; ok {
		return &domain.EnvVar{Key: k, ValueEnc: []byte(v)}, nil
	}
	return nil, domain.ErrNotFound
}
func (e *objEnv) Delete(_ context.Context, _ uuid.UUID, k string) error {
	delete(e.vars, k)
	return nil
}

type memObjRepo struct {
	mu     sync.Mutex
	recs   map[uuid.UUID]*objstore.BucketRecord
	quotas map[string]int64
}

func (m *memObjRepo) Create(_ context.Context, b *objstore.BucketRecord) error {
	c := *b
	m.recs[b.DatabaseID] = &c
	return nil
}
func (m *memObjRepo) ByDatabase(_ context.Context, id uuid.UUID) (*objstore.BucketRecord, error) {
	if r, ok := m.recs[id]; ok {
		c := *r
		return &c, nil
	}
	return nil, objstore.ErrNotFound
}
func (m *memObjRepo) ListByProject(context.Context, uuid.UUID) ([]*objstore.BucketRecord, error) {
	return nil, nil
}
func (m *memObjRepo) Rotate(_ context.Context, id uuid.UUID, ak string, enc []byte) error {
	m.recs[id].AccessKey, m.recs[id].SecretEnc = ak, enc
	return nil
}
func (m *memObjRepo) Update(_ context.Context, id uuid.UUID, pub *bool, max *int64, clear bool) error {
	if pub != nil {
		m.recs[id].Public = *pub
	}
	if clear {
		m.recs[id].MaxBytes = nil
	} else if max != nil {
		m.recs[id].MaxBytes = max
	}
	return nil
}
func (m *memObjRepo) Delete(_ context.Context, id uuid.UUID) error { delete(m.recs, id); return nil }
func (m *memObjRepo) Quota(_ context.Context, s string, id uuid.UUID) (int64, bool, error) {
	v, ok := m.quotas[s+id.String()]
	return v, ok, nil
}
func (m *memObjRepo) EffectiveQuota(ctx context.Context, s string, id uuid.UUID) (int64, error) {
	v, _, _ := m.Quota(ctx, s, id)
	return v, nil
}
func (m *memObjRepo) SetQuota(_ context.Context, s string, id uuid.UUID, max int64) error {
	if max <= 0 {
		delete(m.quotas, s+id.String())
	} else {
		m.quotas[s+id.String()] = max
	}
	return nil
}
func (m *memObjRepo) names(f func(*objstore.BucketRecord) bool) []string {
	var out []string
	for _, r := range m.recs {
		if f(r) {
			out = append(out, r.Bucket)
		}
	}
	return out
}
func (m *memObjRepo) ProjectBucketNames(_ context.Context, p uuid.UUID) ([]string, error) {
	return m.names(func(r *objstore.BucketRecord) bool { return r.ProjectID == p }), nil
}
func (m *memObjRepo) OrgBucketNames(_ context.Context, o uuid.UUID) ([]string, error) {
	return m.names(func(r *objstore.BucketRecord) bool { return r.OrgID == o }), nil
}
func (m *memObjRepo) Secret(b *objstore.BucketRecord) (string, error) {
	return strings.TrimPrefix(string(b.SecretEnc), "enc:"), nil
}
func (m *memObjRepo) Encrypt(s string) ([]byte, error) { return []byte("enc:" + s), nil }

// Meta for the S3 server backed by the same records.
func (m *memObjRepo) Bucket(_ context.Context, n string) (*objstore.BucketInfo, error) {
	for _, r := range m.recs {
		if r.Bucket == n {
			return &objstore.BucketInfo{Name: n, OrgID: r.OrgID.String(), ProjectID: r.ProjectID.String(), Public: r.Public}, nil
		}
	}
	return nil, objstore.ErrNotFound
}
func (m *memObjRepo) Credential(_ context.Context, ak string) (*objstore.Credential, error) {
	for _, r := range m.recs {
		if r.AccessKey == ak {
			s, _ := m.Secret(r)
			return &objstore.Credential{AccessKey: ak, Secret: s, Bucket: r.Bucket}, nil
		}
	}
	return nil, objstore.ErrNotFound
}
func (m *memObjRepo) Limits(ctx context.Context, b string) (objstore.Limits, error) {
	for _, r := range m.recs {
		if r.Bucket == b {
			pn, _ := m.ProjectBucketNames(ctx, r.ProjectID)
			on, _ := m.OrgBucketNames(ctx, r.OrgID)
			pm, _ := m.EffectiveQuota(ctx, "project", r.ProjectID)
			om, _ := m.EffectiveQuota(ctx, "org", r.OrgID)
			return objstore.Limits{ProjectMax: pm, OrgMax: om, ProjectBuckets: pn, OrgBuckets: on}, nil
		}
	}
	return objstore.Limits{}, objstore.ErrNotFound
}

type storageEnv struct {
	router  http.Handler
	org     uuid.UUID
	project uuid.UUID
	repo    *memObjRepo
	env     *objEnv
	store   *objstore.Store
	s3      *httptest.Server
	dbs     *objDBs
}

func newStorageEnv(t *testing.T, role string) *storageEnv {
	t.Helper()
	org, proj := uuid.New(), uuid.New()
	st, err := objstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	repo := &memObjRepo{recs: map[uuid.UUID]*objstore.BucketRecord{}, quotas: map[string]int64{}}
	env := &objEnv{vars: map[string]string{}}
	dbs := &objDBs{rows: map[uuid.UUID]*domain.Database{}}
	s3 := httptest.NewServer(&objstore.Server{Store: st, Meta: repo})
	t.Cleanup(s3.Close)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewStorageHandler(dbs, objOrgs{fakeOrgRepo{role: role}}, fakeAccessProjects{p: &domain.Project{ID: proj, OrgID: org, Slug: "shop"}}, nil, "k", logger)
	h.SetObjstore(ObjstoreConfig{Store: st, Repo: repo, EnvVars: env, InternalEndpoint: "http://host.docker.internal:9000",
		PublicEndpoint: func(string) string { return s3.URL }})
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: uuid.New()})))
		})
	})
	b := "/orgs/{orgID}/projects/{projectID}/storage"
	r.Post(b, h.Create)
	r.Get(b, h.List)
	r.Get(b+"/quota", h.GetProjectQuota)
	r.Put(b+"/quota", h.PutProjectQuota)
	r.Get(b+"/{dbID}", h.Get)
	r.Patch(b+"/{dbID}", h.Update)
	r.Delete(b+"/{dbID}", h.Delete)
	r.Post(b+"/{dbID}/presign", h.Presign)
	r.Post(b+"/{dbID}/rotate", h.Rotate)
	r.Get(b+"/{dbID}/objects", h.ListObjects)
	r.Delete(b+"/{dbID}/objects", h.DeleteObject)
	r.Post(b+"/{dbID}/uploads", h.StartUpload)
	r.Get(b+"/{dbID}/uploads/{uploadID}", h.GetUpload)
	r.Post(b+"/{dbID}/uploads/{uploadID}/complete", h.CompleteUpload)
	r.Get("/orgs/{orgID}/storage/quota", h.GetOrgQuota)
	r.Put("/orgs/{orgID}/storage/quota", h.PutOrgQuota)
	return &storageEnv{r, org, proj, repo, env, st, s3, dbs}
}

func (e *storageEnv) do(method, suffix string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, fmt.Sprintf("/orgs/%s/projects/%s/storage%s", e.org, e.project, suffix), &buf)
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func jsonBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %s", rec.Body)
	}
	return m
}

func (e *storageEnv) create(t *testing.T, name string, extra map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{"name": name}
	for k, v := range extra {
		body[k] = v
	}
	rec := e.do(http.MethodPost, "", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	return jsonBody(t, rec)
}

func httpDo(t *testing.T, method, url string, body io.Reader) (int, []byte, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(method, url, body)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func TestStorageCreateInjectsEnvAndServesObjects(t *testing.T) {
	e := newStorageEnv(t, "owner")
	b := e.create(t, "files", map[string]any{"public": true})
	if b["bucket"] != "shop-acme-files" || b["access_key"] == "" || b["secret_key"] == "" || b["public"] != true {
		t.Fatalf("create response: %v", b)
	}
	for k, want := range map[string]string{
		"STORAGE_FILES_BUCKET": "shop-acme-files", "STORAGE_FILES_ENDPOINT": "http://host.docker.internal:9000",
		"S3_BUCKET": "shop-acme-files", "S3_ENDPOINT": "http://host.docker.internal:9000", "S3_FORCE_PATH_STYLE": "true",
		"S3_ACCESS_KEY_ID": b["access_key"].(string), "S3_SECRET_ACCESS_KEY": b["secret_key"].(string),
	} {
		if e.env.vars[k] != want {
			t.Errorf("env %s = %q, want %q", k, e.env.vars[k], want)
		}
	}
	// second bucket does not steal the standard S3_* names
	e.create(t, "other", nil)
	if e.env.vars["S3_BUCKET"] != "shop-acme-files" || e.env.vars["STORAGE_OTHER_BUCKET"] != "shop-acme-other" {
		t.Fatalf("env after second bucket: %v", e.env.vars)
	}
	// duplicate / invalid names
	if rec := e.do(http.MethodPost, "", map[string]any{"name": "files"}); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate: %d", rec.Code)
	}
	if rec := e.do(http.MethodPost, "", map[string]any{"name": "Bad_Name"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid: %d", rec.Code)
	}
	id := b["id"].(string)

	// presigned PUT then GET against the live S3 server
	var put map[string]any
	rec := e.do(http.MethodPost, "/"+id+"/presign", map[string]any{"key": "a/b.txt", "method": "PUT", "expires": 60})
	if rec.Code != 200 {
		t.Fatalf("presign put: %d %s", rec.Code, rec.Body)
	}
	put = jsonBody(t, rec)
	if code, _, _ := httpDo(t, "PUT", put["url"].(string), strings.NewReader("hello")); code != 200 {
		t.Fatalf("PUT: %d", code)
	}
	rec = e.do(http.MethodPost, "/"+id+"/presign", map[string]any{"key": "a/b.txt"})
	get := jsonBody(t, rec)
	if code, body, _ := httpDo(t, "GET", get["url"].(string), nil); code != 200 || string(body) != "hello" {
		t.Fatalf("GET: %d %q", code, body)
	}
	if rec := e.do(http.MethodPost, "/"+id+"/presign", map[string]any{"key": "x", "expires": 99999999}); rec.Code != 400 {
		t.Fatalf("expiry cap: %d", rec.Code)
	}

	// listing and usage
	rec = e.do(http.MethodGet, "/"+id+"/objects?prefix=a/", nil)
	ls := jsonBody(t, rec)
	if objs := ls["objects"].([]any); len(objs) != 1 {
		t.Fatalf("objects: %v", ls)
	}
	g := jsonBody(t, e.do(http.MethodGet, "/"+id, nil))
	if g["used_bytes"].(float64) != 5 || g["objects"].(float64) != 1 {
		t.Fatalf("usage: %v", g)
	}
	// public bucket: anonymous GET works, no listing
	if code, body, _ := httpDo(t, "GET", e.s3.URL+"/shop-acme-files/a/b.txt", nil); code != 200 || string(body) != "hello" {
		t.Fatalf("public GET: %d", code)
	}
	if rec := e.do(http.MethodDelete, "/"+id+"/objects?key=a/b.txt", nil); rec.Code != 204 {
		t.Fatalf("rm: %d", rec.Code)
	}
	if e.store.Count("shop-acme-files") != 0 {
		t.Fatal("object not removed")
	}
}

func TestStorageRotateInvalidatesOldCredentials(t *testing.T) {
	e := newStorageEnv(t, "owner")
	b := e.create(t, "files", nil)
	id := b["id"].(string)
	oldURL := jsonBody(t, e.do(http.MethodPost, "/"+id+"/presign", map[string]any{"key": "k"}))["url"].(string)
	if code, _, _ := httpDo(t, "GET", oldURL, nil); code != 404 { // valid signature, missing key
		t.Fatalf("before rotation: %d", code)
	}
	nb := jsonBody(t, e.do(http.MethodPost, "/"+id+"/rotate", nil))
	if nb["access_key"] == b["access_key"] || nb["secret_key"] == b["secret_key"] || nb["secret_key"] == "" {
		t.Fatalf("keys not rotated: %v", nb)
	}
	if code, _, _ := httpDo(t, "GET", oldURL, nil); code != 403 {
		t.Fatalf("old URL after rotation: %d", code)
	}
	if e.env.vars["S3_SECRET_ACCESS_KEY"] != nb["secret_key"] || e.env.vars["STORAGE_FILES_ACCESS_KEY"] != nb["access_key"] {
		t.Fatal("env vars not refreshed after rotation")
	}
}

func TestStorageQuotaAndMultipartResume(t *testing.T) {
	e := newStorageEnv(t, "owner")
	b := e.create(t, "files", nil)
	id := b["id"].(string)
	// project quota set by an admin
	if rec := e.do(http.MethodPut, "/quota", map[string]any{"max_bytes": 100}); rec.Code != 200 {
		t.Fatalf("set quota: %d %s", rec.Code, rec.Body)
	}
	q := jsonBody(t, e.do(http.MethodGet, "/quota", nil))
	if q["max_bytes"].(float64) != 100 || q["explicit"] != true {
		t.Fatalf("quota: %v", q)
	}
	url := jsonBody(t, e.do(http.MethodPost, "/"+id+"/presign", map[string]any{"key": "big", "method": "PUT"}))["url"].(string)
	if code, _, _ := httpDo(t, "PUT", url, bytes.NewReader(make([]byte, 101))); code != 403 {
		t.Fatalf("over quota PUT: %d", code)
	}
	if code, _, _ := httpDo(t, "PUT", url, bytes.NewReader(make([]byte, 90))); code != 200 {
		t.Fatalf("within quota PUT: %d", code)
	}
	g := jsonBody(t, e.do(http.MethodGet, "/"+id, nil))
	if g["project_max_bytes"].(float64) != 100 || g["project_used_bytes"].(float64) != 90 {
		t.Fatalf("view quota: %v", g)
	}
	// lift the quota, then a resumable multipart upload
	e.do(http.MethodPut, "/quota", map[string]any{"max_bytes": 0})
	rec := e.do(http.MethodPost, "/"+id+"/uploads", map[string]any{"key": "movie.bin", "size": 12 << 20, "part_size": 5 << 20})
	if rec.Code != 201 {
		t.Fatalf("start upload: %d %s", rec.Code, rec.Body)
	}
	up := jsonBody(t, rec)
	parts := up["parts"].([]any)
	if len(parts) != 3 {
		t.Fatalf("parts: %v", parts)
	}
	uid := up["upload_id"].(string)
	etags := map[int]string{}
	sizes := []int{5 << 20, 5 << 20, 2 << 20}
	send := func(i int) {
		p := parts[i].(map[string]any)
		code, _, h := httpDo(t, "PUT", p["url"].(string), bytes.NewReader(bytes.Repeat([]byte{byte(i + 1)}, sizes[i])))
		if code != 200 {
			t.Fatalf("part %d: %d", i+1, code)
		}
		etags[i+1] = strings.Trim(h.Get("ETag"), `"`)
	}
	send(0)
	// "crash": ask the server which parts exist and resume from there
	have := jsonBody(t, e.do(http.MethodGet, "/"+id+"/uploads/"+uid, nil))["parts"].([]any)
	if len(have) != 1 {
		t.Fatalf("resume state: %v", have)
	}
	send(1)
	send(2)
	rec = e.do(http.MethodPost, "/"+id+"/uploads/"+uid+"/complete", map[string]any{"parts": []map[string]any{
		{"number": 1, "etag": etags[1]}, {"number": 2, "etag": etags[2]}, {"number": 3, "etag": etags[3]}}})
	if rec.Code != 200 {
		t.Fatalf("complete: %d %s", rec.Code, rec.Body)
	}
	if o, err := e.store.Stat("shop-acme-files", "movie.bin"); err != nil || o.Size != 12<<20 {
		t.Fatalf("object: %v %+v", err, o)
	}
}

func TestStoragePermissionsAndQuotaAdmin(t *testing.T) {
	// a viewer cannot create, rotate or change quotas
	v := newStorageEnv(t, "readonly")
	if rec := v.do(http.MethodPost, "", map[string]any{"name": "files"}); rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("viewer create: %d", rec.Code)
	}
	if rec := v.do(http.MethodPut, "/quota", map[string]any{"max_bytes": 5}); rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("viewer quota: %d", rec.Code)
	}
	if rec := v.do(http.MethodGet, "", nil); rec.Code != 200 {
		t.Fatalf("viewer list: %d", rec.Code)
	}
	// a plain member may read the org quota but only owner/admin may change it
	m := newStorageEnv(t, "member")
	req := httptest.NewRequest(http.MethodPut, "/orgs/"+m.org.String()+"/storage/quota", strings.NewReader(`{"max_bytes":1000}`))
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("member org quota: %d", rec.Code)
	}
	o := newStorageEnv(t, "owner")
	req = httptest.NewRequest(http.MethodPut, "/orgs/"+o.org.String()+"/storage/quota", strings.NewReader(`{"max_bytes":1000}`))
	rec = httptest.NewRecorder()
	o.router.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("owner org quota: %d %s", rec.Code, rec.Body)
	}
	b := o.create(t, "files", nil)
	url := jsonBody(t, o.do(http.MethodPost, "/"+b["id"].(string)+"/presign", map[string]any{"key": "k", "method": "PUT"}))["url"].(string)
	if code, _, _ := httpDo(t, "PUT", url, bytes.NewReader(make([]byte, 1001))); code != 403 {
		t.Fatalf("org quota not enforced: %d", code)
	}
}

func TestStorageDeleteRemovesDataAndEnv(t *testing.T) {
	e := newStorageEnv(t, "owner")
	b := e.create(t, "files", nil)
	id := b["id"].(string)
	if rec := e.do(http.MethodDelete, "/"+id, nil); rec.Code != 204 {
		t.Fatalf("delete: %d", rec.Code)
	}
	if e.store.HasBucket("shop-acme-files") {
		t.Fatal("bucket data kept")
	}
	if len(e.env.vars) != 0 {
		t.Fatalf("env vars kept: %v", e.env.vars)
	}
	if rec := e.do(http.MethodGet, "/"+id, nil); rec.Code != 404 {
		t.Fatalf("get after delete: %d", rec.Code)
	}
}

func TestProxyStorageRoute(t *testing.T) {
	e := newStorageEnv(t, "owner")
	b := e.create(t, "files", nil)
	id := b["id"].(string)
	// the S3 server reached through the generic /_proxy/<slug>-storage prefix: the path signed by the client is
	// /bucket/key, the proxy adds /_proxy/shop-storage in front.
	rec := e.do(http.MethodPost, "/"+id+"/presign", map[string]any{"key": "p.txt", "method": "PUT"})
	signed := jsonBody(t, rec)["url"].(string)
	u := strings.TrimPrefix(signed, e.s3.URL)
	srv := &objstore.Server{Store: e.store, Meta: e.repo}
	ph := &ProxyHandler{obj: srv}
	r := chi.NewRouter()
	proj := &domain.Project{ID: e.project, Slug: "shop"}
	r.Handle("/_proxy/{subdomain}/*", http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
		ph.serveStorage(w, rq, proj, chi.URLParam(rq, "subdomain"))
	}))
	// the signature covers the host of the public endpoint: send it as the Host header
	req := httptest.NewRequest("PUT", "/_proxy/shop-storage"+u, strings.NewReader("via proxy"))
	req.Host = strings.TrimPrefix(e.s3.URL, "http://")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("proxy PUT: %d %s", w.Code, w.Body)
	}
	if o, err := e.store.Stat("shop-acme-files", "p.txt"); err != nil || o.Size != 9 {
		t.Fatalf("stored: %v %+v", err, o)
	}
	// another project's host must not see this bucket
	other := &domain.Project{ID: uuid.New(), Slug: "other"}
	r2 := chi.NewRouter()
	r2.Handle("/_proxy/{subdomain}/*", http.HandlerFunc(func(w http.ResponseWriter, rq *http.Request) {
		ph.serveStorage(w, rq, other, chi.URLParam(rq, "subdomain"))
	}))
	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/_proxy/other-storage/shop-acme-files/p.txt", nil)
	r2.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("foreign project host: %d", w.Code)
	}
	// no longer "coming soon"
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/_proxy/shop-storage/", nil))
	if strings.Contains(w.Body.String(), "coming soon") || !strings.Contains(w.Body.String(), "capsule-object-storage") {
		t.Fatalf("info: %s", w.Body)
	}
	_ = time.Now
}
