package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/objstore"
)

// BucketObject is a listed object.
type BucketObject struct {
	Key  string
	Size int64
}

// BucketIO reads and writes objects of the buckets of a project in Capsule's own object store. AI calls use it for inputs (audio,
// images, text to index) and for saving results.
type BucketIO interface {
	Get(ctx context.Context, project uuid.UUID, bucket, key string, max int64) (data []byte, contentType string, err error)
	Put(ctx context.Context, project uuid.UUID, bucket, key string, data []byte, contentType string) error
	List(ctx context.Context, project uuid.UUID, bucket, prefix string, max int) ([]BucketObject, error)
}

// Bucket errors the handler maps to HTTP statuses.
var (
	ErrBucketNotFound = errors.New("bucket not found in this project")
	ErrObjectTooLarge = errors.New("object is larger than the limit")
)

// objstoreBuckets implements BucketIO through the S3 API of the own store, with each bucket's access key.
type objstoreBuckets struct{ c ObjstoreConfig }

// NewObjstoreBuckets returns the BucketIO over the own object store (nil when the store is not enabled).
func NewObjstoreBuckets(c ObjstoreConfig) BucketIO {
	if c.Repo == nil || c.InternalEndpoint == "" {
		return nil
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	return &objstoreBuckets{c: c}
}

func (b *objstoreBuckets) client(ctx context.Context, project uuid.UUID, bucket string) (*s3.Client, *objstore.BucketRecord, error) {
	recs, err := b.c.Repo.ListByProject(ctx, project)
	if err != nil {
		return nil, nil, err
	}
	for _, r := range recs {
		if r.Bucket != bucket {
			continue
		}
		secret, err := b.c.Repo.Secret(r)
		if err != nil {
			return nil, nil, err
		}
		cl := s3.New(s3.Options{
			Region: b.c.Region, BaseEndpoint: aws.String(b.c.InternalEndpoint), UsePathStyle: true,
			Credentials: credentials.NewStaticCredentialsProvider(r.AccessKey, secret, ""),
		})
		return cl, r, nil
	}
	return nil, nil, ErrBucketNotFound
}

func (b *objstoreBuckets) Get(ctx context.Context, project uuid.UUID, bucket, key string, max int64) ([]byte, string, error) {
	cl, _, err := b.client(ctx, project, bucket)
	if err != nil {
		return nil, "", err
	}
	o, err := cl.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return nil, "", fmt.Errorf("reading %s/%s: %w", bucket, key, err)
	}
	defer o.Body.Close()
	if max > 0 && aws.ToInt64(o.ContentLength) > max {
		return nil, "", ErrObjectTooLarge
	}
	data, err := io.ReadAll(io.LimitReader(o.Body, max+1))
	if err != nil {
		return nil, "", err
	}
	if max > 0 && int64(len(data)) > max {
		return nil, "", ErrObjectTooLarge
	}
	return data, aws.ToString(o.ContentType), nil
}

func (b *objstoreBuckets) Put(ctx context.Context, project uuid.UUID, bucket, key string, data []byte, ct string) error {
	cl, _, err := b.client(ctx, project, bucket)
	if err != nil {
		return err
	}
	_, err = cl.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(data), ContentType: aws.String(ct), ContentLength: aws.Int64(int64(len(data)))})
	if err != nil {
		return fmt.Errorf("writing %s/%s: %w", bucket, key, err)
	}
	return nil
}

func (b *objstoreBuckets) List(ctx context.Context, project uuid.UUID, bucket, prefix string, max int) ([]BucketObject, error) {
	cl, _, err := b.client(ctx, project, bucket)
	if err != nil {
		return nil, err
	}
	o, err := cl.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(prefix), MaxKeys: aws.Int32(int32(max))})
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", bucket, err)
	}
	var out []BucketObject
	for _, x := range o.Contents {
		k := aws.ToString(x.Key)
		if strings.HasSuffix(k, "/") {
			continue
		}
		out = append(out, BucketObject{Key: k, Size: aws.ToInt64(x.Size)})
	}
	return out, nil
}
