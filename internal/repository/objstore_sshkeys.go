package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/kynto/capsule/backend/internal/objstore"
)

// SSHKeyRecord is a public key registered for SFTP access to a bucket.
type SSHKeyRecord = objstore.SSHKeyRecord

func (r *ObjstoreRepository) AddSSHKey(ctx context.Context, bucket, name, fingerprint, publicKey string, createdBy *uuid.UUID) (*SSHKeyRecord, error) {
	k := &SSHKeyRecord{ID: uuid.New(), Bucket: bucket, Name: name, Fingerprint: fingerprint, PublicKey: publicKey}
	err := r.pool.QueryRow(ctx, `INSERT INTO objstore_ssh_keys (id, bucket, name, fingerprint, public_key, created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING created_at`,
		k.ID, bucket, name, fingerprint, publicKey, createdBy).Scan(&k.CreatedAt)
	r.invalidate()
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return nil, objstore.ErrKeyExists
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (r *ObjstoreRepository) ListSSHKeys(ctx context.Context, bucket string) ([]*SSHKeyRecord, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, bucket, name, fingerprint, public_key, created_at, last_used_at FROM objstore_ssh_keys WHERE bucket=$1 ORDER BY created_at`, bucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SSHKeyRecord
	for rows.Next() {
		var k SSHKeyRecord
		if err := rows.Scan(&k.ID, &k.Bucket, &k.Name, &k.Fingerprint, &k.PublicKey, &k.CreatedAt, &k.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, &k)
	}
	return out, rows.Err()
}

// DeleteSSHKey removes a key by id or name (or fingerprint) of the bucket.
func (r *ObjstoreRepository) DeleteSSHKey(ctx context.Context, bucket, ref string) error {
	var tag pgconn.CommandTag
	var err error
	if id, perr := uuid.Parse(ref); perr == nil {
		tag, err = r.pool.Exec(ctx, `DELETE FROM objstore_ssh_keys WHERE bucket=$1 AND id=$2`, bucket, id)
	} else {
		tag, err = r.pool.Exec(ctx, `DELETE FROM objstore_ssh_keys WHERE bucket=$1 AND (name=$2 OR fingerprint=$2)`, bucket, ref)
	}
	r.invalidate()
	if err == nil && tag.RowsAffected() == 0 {
		return objstore.ErrNotFound
	}
	return err
}

// ResolveSFTPUser maps an SFTP user name to a bucket: the bucket name, "<project>-<storage name>" or the access key.
// An ambiguous name (the same project slug in two organizations) resolves to nothing.
func (r *ObjstoreRepository) ResolveSFTPUser(ctx context.Context, user string) (string, error) {
	user = strings.TrimSpace(user)
	if user == "" || len(user) > 128 {
		return "", objstore.ErrNotFound
	}
	v, err := r.cached("u:"+user, func() (any, error) {
		rows, err := r.pool.Query(ctx, `SELECT b.bucket FROM objstore_buckets b
			JOIN projects p ON p.id = b.project_id AND p.deleted_at IS NULL
			JOIN databases d ON d.id = b.database_id
			WHERE b.bucket = lower($1) OR b.access_key = $1 OR p.slug || '-' || d.name = lower($1) LIMIT 3`, user)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		seen := map[string]bool{}
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				return nil, err
			}
			seen[n] = true
		}
		if len(seen) != 1 {
			return nil, objstore.ErrNotFound
		}
		for n := range seen {
			return n, nil
		}
		return nil, objstore.ErrNotFound
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// BucketSecret is the decrypted secret key of a bucket (the SFTP password).
func (r *ObjstoreRepository) BucketSecret(ctx context.Context, bucket string) (string, error) {
	v, err := r.cached("s:"+bucket, func() (any, error) {
		b, err := r.ByName(ctx, bucket)
		if err != nil {
			return nil, err
		}
		s, err := r.Secret(b)
		if err != nil {
			return nil, fmt.Errorf("decrypting bucket secret: %w", err)
		}
		return s, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// SSHKeysCached lists the keys of a bucket for logins (cached a few seconds like the other lookups).
func (r *ObjstoreRepository) SSHKeysCached(ctx context.Context, bucket string) ([]*SSHKeyRecord, error) {
	v, err := r.cached("ssh:"+bucket, func() (any, error) { return r.ListSSHKeys(ctx, bucket) })
	if err != nil {
		return nil, err
	}
	return v.([]*SSHKeyRecord), nil
}

func (r *ObjstoreRepository) TouchSSHKey(ctx context.Context, id uuid.UUID) {
	_, _ = r.pool.Exec(ctx, `UPDATE objstore_ssh_keys SET last_used_at=now() WHERE id=$1`, id)
}
