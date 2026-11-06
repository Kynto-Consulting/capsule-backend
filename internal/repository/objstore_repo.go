package repository

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/objstore"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

// ObjstoreRepository persists the control-plane side of Capsule's object store (buckets,
// credentials, quotas) and is the objstore.Meta the S3 server consults on every request.
type ObjstoreRepository struct {
	pool   *pgxpool.Pool
	secret string

	DefaultProjectMax int64 // CAPSULE_OBJSTORE_DEFAULT_PROJECT_BYTES, <=0 unlimited
	DefaultOrgMax     int64 // CAPSULE_OBJSTORE_DEFAULT_ORG_BYTES

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	v   any
	exp time.Time
}

const objCacheTTL = 3 * time.Second

func NewObjstoreRepository(pool *pgxpool.Pool, secret string) *ObjstoreRepository {
	return &ObjstoreRepository{pool: pool, secret: secret, cache: map[string]cacheEntry{}}
}

type BucketRecord = objstore.BucketRecord

// Secret decrypts the bucket's secret key.
func (r *ObjstoreRepository) Secret(b *BucketRecord) (string, error) {
	p, err := crypto.Decrypt(b.SecretEnc, r.secret)
	return string(p), err
}

// Encrypt encrypts a secret key for storage.
func (r *ObjstoreRepository) Encrypt(secret string) ([]byte, error) {
	return crypto.Encrypt([]byte(secret), r.secret)
}

func (r *ObjstoreRepository) invalidate() {
	r.mu.Lock()
	r.cache = map[string]cacheEntry{}
	r.mu.Unlock()
}

func (r *ObjstoreRepository) cached(key string, load func() (any, error)) (any, error) {
	r.mu.Lock()
	if e, ok := r.cache[key]; ok && time.Now().Before(e.exp) {
		r.mu.Unlock()
		return e.v, nil
	}
	r.mu.Unlock()
	v, err := load()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.cache[key] = cacheEntry{v, time.Now().Add(objCacheTTL)}
	r.mu.Unlock()
	return v, nil
}

const bucketCols = `database_id, org_id, project_id, bucket, public_read, access_key, secret_enc, max_bytes, created_at, rotated_at`

func scanBucket(row pgx.Row) (*BucketRecord, error) {
	var b BucketRecord
	err := row.Scan(&b.DatabaseID, &b.OrgID, &b.ProjectID, &b.Bucket, &b.Public, &b.AccessKey, &b.SecretEnc, &b.MaxBytes, &b.CreatedAt, &b.RotatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, objstore.ErrNotFound
	}
	return &b, err
}

func (r *ObjstoreRepository) Create(ctx context.Context, b *BucketRecord) error {
	_, err := r.pool.Exec(ctx, `INSERT INTO objstore_buckets (`+bucketCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now(),NULL)`,
		b.DatabaseID, b.OrgID, b.ProjectID, b.Bucket, b.Public, b.AccessKey, b.SecretEnc, b.MaxBytes)
	r.invalidate()
	return err
}

func (r *ObjstoreRepository) ByDatabase(ctx context.Context, dbID uuid.UUID) (*BucketRecord, error) {
	return scanBucket(r.pool.QueryRow(ctx, `SELECT `+bucketCols+` FROM objstore_buckets WHERE database_id=$1`, dbID))
}

func (r *ObjstoreRepository) ByName(ctx context.Context, bucket string) (*BucketRecord, error) {
	return scanBucket(r.pool.QueryRow(ctx, `SELECT `+bucketCols+` FROM objstore_buckets WHERE bucket=$1`, bucket))
}

func (r *ObjstoreRepository) ListByProject(ctx context.Context, projectID uuid.UUID) ([]*BucketRecord, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+bucketCols+` FROM objstore_buckets WHERE project_id=$1 ORDER BY created_at`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*BucketRecord
	for rows.Next() {
		b, err := scanBucket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// Rotate replaces the access key and secret of a bucket.
func (r *ObjstoreRepository) Rotate(ctx context.Context, dbID uuid.UUID, accessKey string, secretEnc []byte) error {
	tag, err := r.pool.Exec(ctx, `UPDATE objstore_buckets SET access_key=$2, secret_enc=$3, rotated_at=now() WHERE database_id=$1`, dbID, accessKey, secretEnc)
	r.invalidate()
	if err == nil && tag.RowsAffected() == 0 {
		return objstore.ErrNotFound
	}
	return err
}

func (r *ObjstoreRepository) Update(ctx context.Context, dbID uuid.UUID, public *bool, maxBytes *int64, clearMax bool) error {
	if public != nil {
		if _, err := r.pool.Exec(ctx, `UPDATE objstore_buckets SET public_read=$2 WHERE database_id=$1`, dbID, *public); err != nil {
			return err
		}
	}
	if clearMax {
		if _, err := r.pool.Exec(ctx, `UPDATE objstore_buckets SET max_bytes=NULL WHERE database_id=$1`, dbID); err != nil {
			return err
		}
	} else if maxBytes != nil {
		if _, err := r.pool.Exec(ctx, `UPDATE objstore_buckets SET max_bytes=$2 WHERE database_id=$1`, dbID, *maxBytes); err != nil {
			return err
		}
	}
	r.invalidate()
	return nil
}

func (r *ObjstoreRepository) Delete(ctx context.Context, dbID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM objstore_buckets WHERE database_id=$1`, dbID)
	r.invalidate()
	return err
}

// ProjectBucketNames lists the bucket names of a project (backup + usage).
func (r *ObjstoreRepository) ProjectBucketNames(ctx context.Context, projectID uuid.UUID) ([]string, error) {
	return r.names(ctx, `SELECT bucket FROM objstore_buckets WHERE project_id=$1`, projectID)
}

func (r *ObjstoreRepository) OrgBucketNames(ctx context.Context, orgID uuid.UUID) ([]string, error) {
	return r.names(ctx, `SELECT bucket FROM objstore_buckets WHERE org_id=$1`, orgID)
}

func (r *ObjstoreRepository) names(ctx context.Context, q string, arg any) ([]string, error) {
	rows, err := r.pool.Query(ctx, q, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// Quota returns the explicit cap of a scope ("org" | "project"); ok=false when none is set.
func (r *ObjstoreRepository) Quota(ctx context.Context, scope string, id uuid.UUID) (max int64, ok bool, err error) {
	err = r.pool.QueryRow(ctx, `SELECT max_bytes FROM objstore_quotas WHERE scope=$1 AND scope_id=$2`, scope, id).Scan(&max)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return max, err == nil, err
}

// EffectiveQuota is the explicit cap or the platform default (<=0: unlimited).
func (r *ObjstoreRepository) EffectiveQuota(ctx context.Context, scope string, id uuid.UUID) (int64, error) {
	m, ok, err := r.Quota(ctx, scope, id)
	if err != nil {
		return 0, err
	}
	if ok {
		return m, nil
	}
	if scope == "org" {
		return r.DefaultOrgMax, nil
	}
	return r.DefaultProjectMax, nil
}

// SetQuota stores a cap; max<=0 removes it (back to the platform default).
func (r *ObjstoreRepository) SetQuota(ctx context.Context, scope string, id uuid.UUID, max int64) error {
	var err error
	if max <= 0 {
		_, err = r.pool.Exec(ctx, `DELETE FROM objstore_quotas WHERE scope=$1 AND scope_id=$2`, scope, id)
	} else {
		_, err = r.pool.Exec(ctx, `INSERT INTO objstore_quotas (scope, scope_id, max_bytes) VALUES ($1,$2,$3)
			ON CONFLICT (scope, scope_id) DO UPDATE SET max_bytes=EXCLUDED.max_bytes, updated_at=now()`, scope, id, max)
	}
	r.invalidate()
	return err
}

// ── objstore.Meta ───────────────────────────────────────────────────────────

func (r *ObjstoreRepository) Bucket(ctx context.Context, name string) (*objstore.BucketInfo, error) {
	v, err := r.cached("b:"+name, func() (any, error) {
		b, err := r.ByName(ctx, name)
		if err != nil {
			return nil, err
		}
		info := &objstore.BucketInfo{Name: b.Bucket, OrgID: b.OrgID.String(), ProjectID: b.ProjectID.String(), Public: b.Public}
		if b.MaxBytes != nil {
			info.MaxBytes = *b.MaxBytes
		}
		return info, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*objstore.BucketInfo), nil
}

func (r *ObjstoreRepository) Credential(ctx context.Context, accessKey string) (*objstore.Credential, error) {
	v, err := r.cached("k:"+accessKey, func() (any, error) {
		b, err := scanBucket(r.pool.QueryRow(ctx, `SELECT `+bucketCols+` FROM objstore_buckets WHERE access_key=$1`, accessKey))
		if err != nil {
			return nil, err
		}
		sec, err := r.Secret(b)
		if err != nil {
			return nil, fmt.Errorf("decrypting bucket secret: %w", err)
		}
		return &objstore.Credential{AccessKey: b.AccessKey, Secret: sec, Bucket: b.Bucket}, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*objstore.Credential), nil
}

func (r *ObjstoreRepository) Limits(ctx context.Context, bucket string) (objstore.Limits, error) {
	v, err := r.cached("l:"+bucket, func() (any, error) {
		b, err := r.ByName(ctx, bucket)
		if err != nil {
			return nil, err
		}
		var l objstore.Limits
		if l.ProjectMax, err = r.EffectiveQuota(ctx, "project", b.ProjectID); err != nil {
			return nil, err
		}
		if l.OrgMax, err = r.EffectiveQuota(ctx, "org", b.OrgID); err != nil {
			return nil, err
		}
		if l.ProjectBuckets, err = r.ProjectBucketNames(ctx, b.ProjectID); err != nil {
			return nil, err
		}
		if l.OrgBuckets, err = r.OrgBucketNames(ctx, b.OrgID); err != nil {
			return nil, err
		}
		return l, nil
	})
	if err != nil {
		return objstore.Limits{}, err
	}
	return v.(objstore.Limits), nil
}
