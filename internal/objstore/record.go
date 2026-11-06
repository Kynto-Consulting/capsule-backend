package objstore

import (
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
