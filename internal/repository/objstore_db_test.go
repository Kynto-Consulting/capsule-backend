//go:build dbtest

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/objstore"
)

// Run with: go test -tags dbtest ./internal/repository -run Objstore (TEST_DATABASE_URL set, migrations applied).
func TestObjstoreRepoDB(t *testing.T) {
	pool := sharedPool(t)
	ctx := context.Background()
	f := newFx(t, pool)
	org := f.org(f.user("", time.Now()))
	proj := f.project(org, "")
	var dbID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO databases (org_id, project_id, name, engine, version, host, port, db_name, credentials_enc, status)
		VALUES ($1,$2,'files','objstore','1','h',0,'b','','available') RETURNING id`, org, proj).Scan(&dbID); err != nil {
		t.Skipf("fixture insert failed (schema drift): %v", err)
	}
	r := NewObjstoreRepository(pool, "unit-test-secret-key-32-bytes-long!!")
	r.DefaultOrgMax = 777
	enc, err := r.Encrypt("s3cr3t")
	if err != nil {
		t.Fatal(err)
	}
	name := "b-" + uuid.NewString()[:8]
	rec := &objstore.BucketRecord{DatabaseID: dbID, OrgID: org, ProjectID: proj, Bucket: name, AccessKey: "CAPS" + uuid.NewString()[:8], SecretEnc: enc}
	if err := r.Create(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if c, err := r.Credential(ctx, rec.AccessKey); err != nil || c.Secret != "s3cr3t" || c.Bucket != name {
		t.Fatalf("credential: %+v %v", c, err)
	}
	if err := r.SetQuota(ctx, "project", proj, 500); err != nil {
		t.Fatal(err)
	}
	r.invalidate()
	l, err := r.Limits(ctx, name)
	if err != nil || l.ProjectMax != 500 || l.OrgMax != 777 || len(l.ProjectBuckets) != 1 || len(l.OrgBuckets) != 1 {
		t.Fatalf("limits: %+v %v", l, err)
	}
	enc2, _ := r.Encrypt("new")
	if err := r.Rotate(ctx, dbID, "CAPSNEW"+uuid.NewString()[:6], enc2); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Credential(ctx, rec.AccessKey); err == nil {
		t.Fatal("old access key still valid after rotation")
	}
	if err := r.SetQuota(ctx, "project", proj, 0); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := r.Quota(ctx, "project", proj); ok {
		t.Fatal("quota not removed")
	}
	if err := r.Delete(ctx, dbID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ByName(ctx, name); err == nil {
		t.Fatal("bucket not deleted")
	}
}
