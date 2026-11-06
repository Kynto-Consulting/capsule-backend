package objstore

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// BucketRecord is the control-plane row of a bucket (table objstore_buckets).
type BucketRecord struct {
	DatabaseID uuid.UUID
	OrgID      uuid.UUID
	ProjectID  uuid.UUID
	Bucket     string
	Public     bool
	AccessKey  string
	SecretEnc  []byte
	MaxBytes   *int64
	CreatedAt  time.Time
	RotatedAt  *time.Time
}

// ErrKeyExists is returned when the same SSH key or name is already registered for a bucket.
var ErrKeyExists = errors.New("ssh key already registered")

// SSHKeyRecord is a public key registered for SFTP access to a bucket (table objstore_ssh_keys).
type SSHKeyRecord struct {
	ID          uuid.UUID
	Bucket      string
	Name        string
	Fingerprint string
	PublicKey   string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
}
