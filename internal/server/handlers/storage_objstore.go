package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/objstore"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// EngineObjstore is the databases.engine value of a bucket of Capsule's own object store.
const EngineObjstore = "objstore"

// ObjstoreRepo is the persistence the storage handler needs for Capsule's own object store.
type ObjstoreRepo interface {
	Create(ctx context.Context, b *objstore.BucketRecord) error
	ByDatabase(ctx context.Context, dbID uuid.UUID) (*objstore.BucketRecord, error)
	ListByProject(ctx context.Context, projectID uuid.UUID) ([]*objstore.BucketRecord, error)
	Rotate(ctx context.Context, dbID uuid.UUID, accessKey string, secretEnc []byte) error
	Update(ctx context.Context, dbID uuid.UUID, public *bool, maxBytes *int64, clearMax bool) error
	Delete(ctx context.Context, dbID uuid.UUID) error
	Quota(ctx context.Context, scope string, id uuid.UUID) (int64, bool, error)
	EffectiveQuota(ctx context.Context, scope string, id uuid.UUID) (int64, error)
	SetQuota(ctx context.Context, scope string, id uuid.UUID, max int64) error
	ProjectBucketNames(ctx context.Context, projectID uuid.UUID) ([]string, error)
	OrgBucketNames(ctx context.Context, orgID uuid.UUID) ([]string, error)
	Secret(b *objstore.BucketRecord) (string, error)
	Encrypt(secret string) ([]byte, error)
}

// ObjstoreConfig wires Capsule's own object store into the storage handler.
type ObjstoreConfig struct {
	Store            *objstore.Store
	Repo             ObjstoreRepo
	EnvVars          domain.EnvVarRepository
	PublicEndpoint   func(projectSlug string) string // https://<slug>-storage.apps.<zone>
	InternalEndpoint string                          // http://host.docker.internal:9000
	Region           string
}

// SetObjstore enables Capsule's own object store; without it `storage create` keeps provisioning AWS buckets.
func (h *StorageHandler) SetObjstore(c ObjstoreConfig) {
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	h.obj = &c
}

var storageNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,29}[a-z0-9]$`)

func newKeyPair() (access, secret string, err error) {
	a, s := make([]byte, 8), make([]byte, 20)
	if _, err = rand.Read(a); err != nil {
		return
	}
	if _, err = rand.Read(s); err != nil {
		return
	}
	return "CAPS" + strings.ToUpper(hex.EncodeToString(a)), hex.EncodeToString(s), nil
}

func envPrefix(name string) string {
	return "STORAGE_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
}

// setEnv writes the connection variables of a bucket into the project's environment, so the next
// deployment gets them: STORAGE_<NAME>_* always, plus the standard S3_* aliases for the first bucket.
func (h *StorageHandler) setEnv(ctx context.Context, projectID uuid.UUID, slug, name string, rec *objstore.BucketRecord, secret string) {
	if h.obj == nil || h.obj.EnvVars == nil {
		return
	}
	vals := map[string]string{
		"ENDPOINT":        h.obj.InternalEndpoint,
		"PUBLIC_ENDPOINT": h.obj.PublicEndpoint(slug),
		"BUCKET":          rec.Bucket,
		"ACCESS_KEY":      rec.AccessKey,
		"SECRET_KEY":      secret,
		"REGION":          h.obj.Region,
	}
	set := func(key, val string, secretVar bool) {
		if _, err := h.obj.EnvVars.Upsert(ctx, &domain.EnvVar{ProjectID: projectID, Key: key, ValueEnc: []byte(val), IsSecret: secretVar, Scope: "runtime"}); err != nil {
			h.logger.Warn("storage env var not written", "key", key, "error", err)
		}
	}
	p := envPrefix(name)
	for k, v := range vals {
		set(p+k, v, k == "SECRET_KEY" || k == "ACCESS_KEY")
	}
	alias := true
	if cur, err := h.obj.EnvVars.GetByKey(ctx, projectID, "S3_BUCKET"); err == nil && string(cur.ValueEnc) != rec.Bucket {
		alias = false // another bucket already owns the standard names
	}
	if alias {
		set("S3_ENDPOINT", vals["ENDPOINT"], false)
		set("S3_BUCKET", rec.Bucket, false)
		set("S3_ACCESS_KEY_ID", rec.AccessKey, true)
		set("S3_SECRET_ACCESS_KEY", secret, true)
		set("S3_REGION", h.obj.Region, false)
		set("S3_FORCE_PATH_STYLE", "true", false)
	}
}

func (h *StorageHandler) clearEnv(ctx context.Context, projectID uuid.UUID, name string, rec *objstore.BucketRecord) {
	if h.obj == nil || h.obj.EnvVars == nil {
		return
	}
	for _, k := range []string{"ENDPOINT", "PUBLIC_ENDPOINT", "BUCKET", "ACCESS_KEY", "SECRET_KEY", "REGION"} {
		_ = h.obj.EnvVars.Delete(ctx, projectID, envPrefix(name)+k)
	}
	if cur, err := h.obj.EnvVars.GetByKey(ctx, projectID, "S3_BUCKET"); err == nil && string(cur.ValueEnc) == rec.Bucket {
		for _, k := range []string{"S3_ENDPOINT", "S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY", "S3_REGION", "S3_FORCE_PATH_STYLE"} {
			_ = h.obj.EnvVars.Delete(ctx, projectID, k)
		}
	}
}

type bucketView struct {
	*domain.Database
	Bucket           string  `json:"bucket"`
	Public           bool    `json:"public"`
	Endpoint         string  `json:"endpoint"`
	InternalEndpoint string  `json:"internal_endpoint"`
	Region           string  `json:"region"`
	AccessKey        string  `json:"access_key"`
	SecretKey        string  `json:"secret_key,omitempty"`
	UsedBytes        int64   `json:"used_bytes"`
	Objects          int     `json:"objects"`
	MaxBytes         *int64  `json:"max_bytes,omitempty"`
	ProjectUsedBytes int64   `json:"project_used_bytes"`
	ProjectMaxBytes  int64   `json:"project_max_bytes"`
	OrgUsedBytes     int64   `json:"org_used_bytes"`
	OrgMaxBytes      int64   `json:"org_max_bytes"`
	RotatedAt        *string `json:"rotated_at,omitempty"`
}

func (h *StorageHandler) usage(ctx context.Context, names []string) int64 {
	var t int64
	for _, n := range names {
		t += h.obj.Store.Usage(n)
	}
	return t
}

func (h *StorageHandler) view(ctx context.Context, db *domain.Database, rec *objstore.BucketRecord, slug string, reveal bool) *bucketView {
	v := &bucketView{Database: db, Bucket: rec.Bucket, Public: rec.Public, Endpoint: h.obj.PublicEndpoint(slug),
		InternalEndpoint: h.obj.InternalEndpoint, Region: h.obj.Region, AccessKey: rec.AccessKey, MaxBytes: rec.MaxBytes,
		UsedBytes: h.obj.Store.Usage(rec.Bucket), Objects: h.obj.Store.Count(rec.Bucket)}
	if rec.RotatedAt != nil {
		s := rec.RotatedAt.UTC().Format(time.RFC3339)
		v.RotatedAt = &s
	}
	if reveal {
		v.SecretKey, _ = h.obj.Repo.Secret(rec)
	}
	if names, err := h.obj.Repo.ProjectBucketNames(ctx, rec.ProjectID); err == nil {
		v.ProjectUsedBytes = h.usage(ctx, names)
	}
	if names, err := h.obj.Repo.OrgBucketNames(ctx, rec.OrgID); err == nil {
		v.OrgUsedBytes = h.usage(ctx, names)
	}
	v.ProjectMaxBytes, _ = h.obj.Repo.EffectiveQuota(ctx, "project", rec.ProjectID)
	v.OrgMaxBytes, _ = h.obj.Repo.EffectiveQuota(ctx, "org", rec.OrgID)
	return v
}

func (h *StorageHandler) canReveal(r *http.Request, orgID, projectID uuid.UUID) bool {
	u := middleware.GetUser(r.Context())
	if u == nil {
		return false
	}
	ok, _ := h.service(h.orgs).Can(r.Context(), u.ID, orgID, projectID, authz.ProjectEnvReveal)
	return ok
}

// createObjstore provisions a bucket of the own object store.
func (h *StorageHandler) createObjstore(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, project *domain.Project, name string, public bool, maxBytes *int64) {
	if !storageNameRe.MatchString(name) {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name must be 3-31 characters: lowercase letters, digits and '-', starting and ending with a letter or digit")
		return
	}
	org, err := h.orgs.GetByID(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get organization")
		return
	}
	bucket := fmt.Sprintf("%s-%s-%s", project.Slug, org.Slug, name)
	if len(bucket) > 63 {
		bucket = bucket[:63]
	}
	bucket = strings.Trim(strings.ToLower(bucket), "-.")
	if !objstore.ValidBucketName(bucket) {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "cannot derive a valid bucket name from project, organization and name")
		return
	}
	existing, _ := h.dbs.ListByProject(r.Context(), project.ID)
	for _, d := range existing {
		if d.Engine == EngineObjstore && d.Name == name {
			respondError(w, http.StatusConflict, "CONFLICT", "a storage bucket with this name already exists in the project")
			return
		}
	}
	if h.obj.Store.HasBucket(bucket) {
		respondError(w, http.StatusConflict, "CONFLICT", "bucket name already in use")
		return
	}
	access, secret, err := newKeyPair()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate credentials")
		return
	}
	enc, err := h.obj.Repo.Encrypt(secret)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to encrypt credentials")
		return
	}
	db, err := h.dbs.Create(r.Context(), &domain.Database{OrgID: orgID, ProjectID: &project.ID, Name: name, Engine: EngineObjstore, Version: "1",
		Host: strings.TrimPrefix(strings.TrimPrefix(h.obj.InternalEndpoint, "http://"), "https://"), Port: 0, DBName: bucket, Status: "available", CredentialsEnc: []byte{}})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create storage record")
		return
	}
	rec := &objstore.BucketRecord{DatabaseID: db.ID, OrgID: orgID, ProjectID: project.ID, Bucket: bucket, Public: public, AccessKey: access, SecretEnc: enc, MaxBytes: maxBytes}
	if err := h.obj.Store.CreateBucket(bucket); err == nil {
		err = h.obj.Repo.Create(r.Context(), rec)
		if err != nil {
			_ = h.obj.Store.DeleteBucket(bucket, true)
		}
	}
	if err != nil || !h.obj.Store.HasBucket(bucket) {
		_ = h.dbs.Delete(r.Context(), db.ID)
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create bucket")
		return
	}
	h.setEnv(r.Context(), project.ID, project.Slug, name, rec, secret)
	v := h.view(r.Context(), db, rec, project.Slug, true)
	respondJSON(w, http.StatusCreated, v)
}

// loadObjstore authorizes the request and loads an own-store bucket of the URL's project.
func (h *StorageHandler) loadObjstore(w http.ResponseWriter, r *http.Request, act authz.Action) (*domain.Database, *objstore.BucketRecord, *domain.Project, bool) {
	if h.obj == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Capsule object storage is not enabled on this platform")
		return nil, nil, nil, false
	}
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return nil, nil, nil, false
	}
	dbID, err := uuid.Parse(chi.URLParam(r, "dbID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid storage id")
		return nil, nil, nil, false
	}
	projectID, ok := h.authorizeRoute(w, r, h.orgs, orgID, act)
	if !ok {
		return nil, nil, nil, false
	}
	db, err := h.dbs.GetByID(r.Context(), dbID)
	if err == domain.ErrNotFound || (err == nil && (db.ProjectID == nil || *db.ProjectID != projectID || db.OrgID != orgID)) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "storage bucket not found")
		return nil, nil, nil, false
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to load storage bucket")
		return nil, nil, nil, false
	}
	if db.Engine != EngineObjstore {
		respondError(w, http.StatusBadRequest, "UNSUPPORTED", "this bucket is an AWS S3 bucket created before Capsule storage; it supports get, delete and presign only")
		return nil, nil, nil, false
	}
	rec, err := h.obj.Repo.ByDatabase(r.Context(), dbID)
	if err != nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "storage bucket not found")
		return nil, nil, nil, false
	}
	project, err := h.projects.GetByID(r.Context(), projectID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get project")
		return nil, nil, nil, false
	}
	return db, rec, project, true
}

func (h *StorageHandler) getObjstore(w http.ResponseWriter, r *http.Request, db *domain.Database, rec *objstore.BucketRecord, project *domain.Project) {
	respondJSON(w, http.StatusOK, h.view(r.Context(), db, rec, project.Slug, h.canReveal(r, db.OrgID, project.ID)))
}

// Update changes the visibility and the per-bucket cap.  PATCH {public?, max_bytes?}  (max_bytes 0 clears it)
func (h *StorageHandler) Update(w http.ResponseWriter, r *http.Request) {
	db, rec, project, ok := h.loadObjstore(w, r, authz.ProjectDatabases)
	if !ok {
		return
	}
	var req struct {
		Public   *bool  `json:"public"`
		MaxBytes *int64 `json:"max_bytes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.MaxBytes != nil && *req.MaxBytes < 0) {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	clear := req.MaxBytes != nil && *req.MaxBytes == 0
	if err := h.obj.Repo.Update(r.Context(), db.ID, req.Public, req.MaxBytes, clear); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update bucket")
		return
	}
	rec, _ = h.obj.Repo.ByDatabase(r.Context(), db.ID)
	respondJSON(w, http.StatusOK, h.view(r.Context(), db, rec, project.Slug, false))
}

// Rotate issues a new access key and secret; the old pair stops working at once.
func (h *StorageHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	db, rec, project, ok := h.loadObjstore(w, r, authz.ProjectDatabases)
	if !ok {
		return
	}
	access, secret, err := newKeyPair()
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate credentials")
		return
	}
	enc, err := h.obj.Repo.Encrypt(secret)
	if err == nil {
		err = h.obj.Repo.Rotate(r.Context(), db.ID, access, enc)
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to rotate credentials")
		return
	}
	rec, _ = h.obj.Repo.ByDatabase(r.Context(), db.ID)
	h.setEnv(r.Context(), project.ID, project.Slug, db.Name, rec, secret)
	respondJSON(w, http.StatusOK, h.view(r.Context(), db, rec, project.Slug, true))
}

func (h *StorageHandler) deleteObjstore(w http.ResponseWriter, r *http.Request, db *domain.Database, rec *objstore.BucketRecord, project *domain.Project) {
	if err := h.obj.Repo.Delete(r.Context(), db.ID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete bucket")
		return
	}
	if err := h.obj.Store.DeleteBucket(rec.Bucket, true); err != nil && !errors.Is(err, objstore.ErrNotFound) {
		h.logger.Error("deleting bucket data", "bucket", rec.Bucket, "error", err)
	}
	_ = h.dbs.Delete(r.Context(), db.ID)
	h.clearEnv(r.Context(), project.ID, db.Name, rec)
	respondNoContent(w)
}

// CleanupProject removes the data of every own-store bucket of a deleted project.
func (h *StorageHandler) CleanupProject(projectID uuid.UUID) {
	if h.obj == nil {
		return
	}
	ctx := context.Background()
	names, err := h.obj.Repo.ProjectBucketNames(ctx, projectID)
	if err != nil {
		h.logger.Error("storage cleanup", "project_id", projectID, "error", err)
		return
	}
	for _, n := range names {
		_ = h.obj.Store.DeleteBucket(n, true)
	}
}

// PresignObjstore handles POST .../presign {key, expires, method: GET|PUT} for an own-store bucket.
func (h *StorageHandler) presignObjstore(w http.ResponseWriter, r *http.Request, rec *objstore.BucketRecord, project *domain.Project) {
	var req struct {
		Key     string `json:"key"`
		Expires int    `json:"expires"`
		Method  string `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "key is required")
		return
	}
	if req.Expires <= 0 {
		req.Expires = 3600
	}
	m := strings.ToUpper(req.Method)
	if m == "" {
		m = "GET"
	}
	if m != "GET" && m != "PUT" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "method must be GET or PUT")
		return
	}
	if req.Expires > 7*24*3600 {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "expires must be at most 604800 seconds (7 days)")
		return
	}
	secret, err := h.obj.Repo.Secret(rec)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to read credentials")
		return
	}
	now := time.Now()
	url, err := objstore.Presign(m, h.obj.PublicEndpoint(project.Slug), h.obj.Region, rec.Bucket, req.Key, rec.AccessKey, secret, time.Duration(req.Expires)*time.Second, now, nil)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to presign request")
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"url": url, "method": m, "expires_at": now.Add(time.Duration(req.Expires) * time.Second).UTC().Format(time.RFC3339)})
}

// Objects: GET .../storage/{dbID}/objects?prefix=&delimiter=&after=&limit=
func (h *StorageHandler) ListObjects(w http.ResponseWriter, r *http.Request) {
	_, rec, _, ok := h.loadObjstore(w, r, authz.ProjectRead)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit := 1000
	fmt.Sscanf(q.Get("limit"), "%d", &limit)
	res, err := h.obj.Store.List(rec.Bucket, q.Get("prefix"), q.Get("delimiter"), q.Get("after"), limit)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list objects")
		return
	}
	objs := res.Objects
	if objs == nil {
		objs = []objstore.Object{}
	}
	prefixes := res.CommonPrefixes
	if prefixes == nil {
		prefixes = []string{}
	}
	respondJSON(w, http.StatusOK, map[string]any{"objects": objs, "prefixes": prefixes, "truncated": res.Truncated, "next": res.Next})
}

// DeleteObject: DELETE .../storage/{dbID}/objects?key=
func (h *StorageHandler) DeleteObject(w http.ResponseWriter, r *http.Request) {
	_, rec, _, ok := h.loadObjstore(w, r, authz.ProjectOps)
	if !ok {
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "key is required")
		return
	}
	if err := h.obj.Store.Delete(rec.Bucket, key); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete object")
		return
	}
	respondNoContent(w)
}

const (
	defaultPartSize = 16 << 20
	maxParts        = 10000
	partURLTTL      = 6 * time.Hour
)

// StartUpload begins a resumable multipart upload:
// POST .../storage/{dbID}/uploads {key, content_type, size, part_size?} → upload id + presigned part URLs.
func (h *StorageHandler) StartUpload(w http.ResponseWriter, r *http.Request) {
	_, rec, project, ok := h.loadObjstore(w, r, authz.ProjectOps)
	if !ok {
		return
	}
	var req struct {
		Key         string `json:"key"`
		ContentType string `json:"content_type"`
		Size        int64  `json:"size"`
		PartSize    int64  `json:"part_size"`
		UploadID    string `json:"upload_id"` // resume: presign the parts of an existing upload again
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" || req.Size <= 0 {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "key and size are required")
		return
	}
	if req.PartSize < 5<<20 {
		req.PartSize = defaultPartSize
	}
	for (req.Size+req.PartSize-1)/req.PartSize > maxParts {
		req.PartSize *= 2
	}
	id := req.UploadID
	if id != "" {
		if k, err := h.obj.Store.UploadKey(rec.Bucket, id); err != nil || k != req.Key {
			respondError(w, http.StatusNotFound, "NOT_FOUND", "upload not found")
			return
		}
	} else {
		var err error
		if id, err = h.obj.Store.InitUpload(rec.Bucket, req.Key, req.ContentType); err != nil {
			respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
	}
	secret, err := h.obj.Repo.Secret(rec)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to read credentials")
		return
	}
	n := int((req.Size + req.PartSize - 1) / req.PartSize)
	type part struct {
		Number int    `json:"number"`
		Size   int64  `json:"size"`
		URL    string `json:"url"`
	}
	parts := make([]part, n)
	now := time.Now()
	for i := range parts {
		sz := req.PartSize
		if i == n-1 {
			sz = req.Size - int64(n-1)*req.PartSize
		}
		u, err := objstore.Presign("PUT", h.obj.PublicEndpoint(project.Slug), h.obj.Region, rec.Bucket, req.Key, rec.AccessKey, secret, partURLTTL, now,
			map[string][]string{"partNumber": {fmt.Sprint(i + 1)}, "uploadId": {id}})
		if err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to presign part")
			return
		}
		parts[i] = part{i + 1, sz, u}
	}
	respondJSON(w, http.StatusCreated, map[string]any{"upload_id": id, "key": req.Key, "part_size": req.PartSize, "parts": parts,
		"expires_at": now.Add(partURLTTL).UTC().Format(time.RFC3339)})
}

// GetUpload lists the parts already stored, so a client can resume.  GET .../uploads/{uploadID}
func (h *StorageHandler) GetUpload(w http.ResponseWriter, r *http.Request) {
	_, rec, _, ok := h.loadObjstore(w, r, authz.ProjectOps)
	if !ok {
		return
	}
	ps, err := h.obj.Store.Parts(rec.Bucket, chi.URLParam(r, "uploadID"))
	if err != nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "upload not found")
		return
	}
	type part struct {
		Number int    `json:"number"`
		Size   int64  `json:"size"`
		ETag   string `json:"etag"`
	}
	out := make([]part, len(ps))
	for i, p := range ps {
		out[i] = part{p.Number, p.Size, p.ETag}
	}
	respondJSON(w, http.StatusOK, map[string]any{"parts": out})
}

// CompleteUpload assembles the object.  POST .../uploads/{uploadID}/complete {parts:[{number,etag}]}
func (h *StorageHandler) CompleteUpload(w http.ResponseWriter, r *http.Request) {
	_, rec, _, ok := h.loadObjstore(w, r, authz.ProjectOps)
	if !ok {
		return
	}
	var req struct {
		Parts []struct {
			Number int    `json:"number"`
			ETag   string `json:"etag"`
		} `json:"parts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Parts) == 0 {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "parts are required")
		return
	}
	id := chi.URLParam(r, "uploadID")
	want := make([]objstore.Part, len(req.Parts))
	for i, p := range req.Parts {
		want[i] = objstore.Part{Number: p.Number, ETag: p.ETag}
	}
	key, err := h.obj.Store.UploadKey(rec.Bucket, id)
	if err != nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "upload not found")
		return
	}
	room, err := h.roomFor(r.Context(), rec, key, id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check quota")
		return
	}
	o, err := h.obj.Store.CompleteUpload(rec.Bucket, id, want, room)
	switch {
	case errors.Is(err, objstore.ErrQuota):
		respondError(w, http.StatusForbidden, "QUOTA_EXCEEDED", "storage quota exceeded")
	case errors.Is(err, objstore.ErrBadPart):
		respondError(w, http.StatusBadRequest, "INVALID_PART", "one or more parts are missing or their checksum does not match")
	case err != nil:
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to complete upload")
	default:
		respondJSON(w, http.StatusOK, o)
	}
}

// roomFor is the largest object that may be assembled now (parts already counted by the S3 side).
func (h *StorageHandler) roomFor(ctx context.Context, rec *objstore.BucketRecord, key, uploadID string) (int64, error) {
	best := int64(-1)
	apply := func(max, used int64) {
		if max <= 0 {
			return
		}
		left := max - used
		if left < 0 {
			left = 0
		}
		if best < 0 || left < best {
			best = left
		}
	}
	used := func(names []string) int64 {
		var t int64
		for _, n := range names {
			t += h.obj.Store.Usage(n) + h.obj.Store.Pending(n)
		}
		return t
	}
	pn, err := h.obj.Repo.ProjectBucketNames(ctx, rec.ProjectID)
	if err != nil {
		return 0, err
	}
	on, err := h.obj.Repo.OrgBucketNames(ctx, rec.OrgID)
	if err != nil {
		return 0, err
	}
	pm, err := h.obj.Repo.EffectiveQuota(ctx, "project", rec.ProjectID)
	if err != nil {
		return 0, err
	}
	om, err := h.obj.Repo.EffectiveQuota(ctx, "org", rec.OrgID)
	if err != nil {
		return 0, err
	}
	if rec.MaxBytes != nil {
		apply(*rec.MaxBytes, h.obj.Store.Usage(rec.Bucket)+h.obj.Store.Pending(rec.Bucket))
	}
	apply(pm, used(pn))
	apply(om, used(on))
	if best >= 0 {
		best += h.obj.Store.UploadSize(rec.Bucket, uploadID)
		if o, err := h.obj.Store.Stat(rec.Bucket, key); err == nil {
			best += o.Size
		}
	}
	return best, nil
}

// AbortUpload: DELETE .../uploads/{uploadID}
func (h *StorageHandler) AbortUpload(w http.ResponseWriter, r *http.Request) {
	_, rec, _, ok := h.loadObjstore(w, r, authz.ProjectOps)
	if !ok {
		return
	}
	if err := h.obj.Store.AbortUpload(rec.Bucket, chi.URLParam(r, "uploadID")); err != nil {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "upload not found")
		return
	}
	respondNoContent(w)
}

// ── quotas ──────────────────────────────────────────────────────────────────

type quotaView struct {
	Scope     string `json:"scope"`
	MaxBytes  int64  `json:"max_bytes"` // 0 = unlimited
	Explicit  bool   `json:"explicit"`  // false = platform default
	UsedBytes int64  `json:"used_bytes"`
}

func (h *StorageHandler) quota(ctx context.Context, scope string, id uuid.UUID) quotaView {
	max, explicit, _ := h.obj.Repo.Quota(ctx, scope, id)
	if !explicit {
		max, _ = h.obj.Repo.EffectiveQuota(ctx, scope, id)
	}
	if max < 0 {
		max = 0
	}
	var names []string
	if scope == "org" {
		names, _ = h.obj.Repo.OrgBucketNames(ctx, id)
	} else {
		names, _ = h.obj.Repo.ProjectBucketNames(ctx, id)
	}
	return quotaView{Scope: scope, MaxBytes: max, Explicit: explicit, UsedBytes: h.usage(ctx, names)}
}

func (h *StorageHandler) putQuota(w http.ResponseWriter, r *http.Request, orgID uuid.UUID, scope string, id uuid.UUID) {
	u := middleware.GetUser(r.Context())
	role := ""
	if u != nil {
		role, _ = h.orgs.GetMemberRole(r.Context(), orgID, u.ID)
	}
	if role != "owner" && role != "admin" {
		respondError(w, http.StatusForbidden, "FORBIDDEN", "only organization owners and admins can change storage quotas")
		return
	}
	var req struct {
		MaxBytes int64 `json:"max_bytes"` // 0 restores the platform default
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MaxBytes < 0 {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "max_bytes must be a non-negative integer")
		return
	}
	if err := h.obj.Repo.SetQuota(r.Context(), scope, id, req.MaxBytes); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to save quota")
		return
	}
	respondJSON(w, http.StatusOK, h.quota(r.Context(), scope, id))
}

func (h *StorageHandler) quotaIDs(w http.ResponseWriter, r *http.Request, scope string, act authz.Action) (uuid.UUID, uuid.UUID, bool) {
	if h.obj == nil {
		respondError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Capsule object storage is not enabled on this platform")
		return uuid.Nil, uuid.Nil, false
	}
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid org id")
		return uuid.Nil, uuid.Nil, false
	}
	if scope == "org" {
		u := middleware.GetUser(r.Context())
		if u == nil {
			respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return uuid.Nil, uuid.Nil, false
		}
		if ok, _ := h.orgs.IsMember(r.Context(), orgID, u.ID); !ok {
			respondError(w, http.StatusForbidden, "FORBIDDEN", "not a member")
			return uuid.Nil, uuid.Nil, false
		}
		return orgID, orgID, true
	}
	projectID, ok := h.authorizeRoute(w, r, h.orgs, orgID, act)
	return orgID, projectID, ok
}

// GetOrgQuota / PutOrgQuota: /orgs/{orgID}/storage/quota
func (h *StorageHandler) GetOrgQuota(w http.ResponseWriter, r *http.Request) {
	_, id, ok := h.quotaIDs(w, r, "org", authz.Action(""))
	if ok {
		respondJSON(w, http.StatusOK, h.quota(r.Context(), "org", id))
	}
}

func (h *StorageHandler) PutOrgQuota(w http.ResponseWriter, r *http.Request) {
	orgID, id, ok := h.quotaIDs(w, r, "org", authz.Action(""))
	if ok {
		h.putQuota(w, r, orgID, "org", id)
	}
}

// GetProjectQuota / PutProjectQuota: /orgs/{orgID}/projects/{projectID}/storage/quota
func (h *StorageHandler) GetProjectQuota(w http.ResponseWriter, r *http.Request) {
	_, id, ok := h.quotaIDs(w, r, "project", authz.ProjectRead)
	if ok {
		respondJSON(w, http.StatusOK, h.quota(r.Context(), "project", id))
	}
}

func (h *StorageHandler) PutProjectQuota(w http.ResponseWriter, r *http.Request) {
	orgID, id, ok := h.quotaIDs(w, r, "project", authz.ProjectDatabases)
	if ok {
		h.putQuota(w, r, orgID, "project", id)
	}
}
