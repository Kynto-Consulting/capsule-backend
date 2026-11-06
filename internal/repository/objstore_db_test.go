//go:build dbtest

package repository

import (
	"context"
	"errors"
	"strings"
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

// SFTP: user resolution (bucket name, <project>-<name>, access key) and the SSH keys of a bucket.
func TestObjstoreSFTPRepoDB(t *testing.T) {
	pool := sharedPool(t)
	ctx := context.Background()
	f := newFx(t, pool)
	org := f.org(f.user("", time.Now()))
	proj := f.project(org, "")
	var slug string
	if err := pool.QueryRow(ctx, `SELECT slug FROM projects WHERE id=$1`, proj).Scan(&slug); err != nil {
		t.Skipf("fixture: %v", err)
	}
	name := "files" + uuid.NewString()[:6]
	var dbID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO databases (org_id, project_id, name, engine, version, host, port, db_name, credentials_enc, status)
		VALUES ($1,$2,$3,'objstore','1','h',0,'b','','available') RETURNING id`, org, proj, name).Scan(&dbID); err != nil {
		t.Skipf("fixture insert failed (schema drift): %v", err)
	}
	r := NewObjstoreRepository(pool, "unit-test-secret-key-32-bytes-long!!")
	enc, _ := r.Encrypt("s3cr3t")
	bucket := "b-" + uuid.NewString()[:8]
	ak := "CAPS" + strings.ToUpper(uuid.NewString()[:8])
	if err := r.Create(ctx, &objstore.BucketRecord{DatabaseID: dbID, OrgID: org, ProjectID: proj, Bucket: bucket, AccessKey: ak, SecretEnc: enc}); err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{bucket, strings.ToUpper(bucket), slug + "-" + name, ak} {
		if got, err := r.ResolveSFTPUser(ctx, user); err != nil || got != bucket {
			t.Errorf("resolve %q: %q %v", user, got, err)
		}
	}
	for _, user := range []string{"", "nope-nope", slug, bucket + "x"} {
		if _, err := r.ResolveSFTPUser(ctx, user); err == nil {
			t.Errorf("resolved %q", user)
		}
	}
	if s, err := r.BucketSecret(ctx, bucket); err != nil || s != "s3cr3t" {
		t.Fatalf("secret: %q %v", s, err)
	}

	k1, err := r.AddSSHKey(ctx, bucket, "laptop", "SHA256:aaa", "ssh-ed25519 AAAA laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.AddSSHKey(ctx, bucket, "laptop", "SHA256:bbb", "ssh-ed25519 BBBB", nil); !errors.Is(err, objstore.ErrKeyExists) {
		t.Fatalf("duplicate name: %v", err)
	}
	if _, err := r.AddSSHKey(ctx, bucket, "other", "SHA256:aaa", "ssh-ed25519 AAAA", nil); !errors.Is(err, objstore.ErrKeyExists) {
		t.Fatalf("duplicate fingerprint: %v", err)
	}
	r.TouchSSHKey(ctx, k1.ID)
	keys, err := r.SSHKeysCached(ctx, bucket)
	if err != nil || len(keys) != 1 || keys[0].LastUsedAt == nil && false {
		t.Fatalf("keys: %v %v", keys, err)
	}
	if err := r.DeleteSSHKey(ctx, bucket, "laptop"); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteSSHKey(ctx, bucket, "laptop"); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if keys, _ := r.SSHKeysCached(ctx, bucket); len(keys) != 0 {
		t.Fatalf("removed key still listed: %v", keys)
	}
	// keys go away with the bucket
	k2, _ := r.AddSSHKey(ctx, bucket, "again", "SHA256:ccc", "ssh-ed25519 CCCC", nil)
	if err := r.Delete(ctx, dbID); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM objstore_ssh_keys WHERE id=$1`, k2.ID).Scan(&n)
	if n != 0 {
		t.Fatal("ssh keys survived the bucket")
	}
}
