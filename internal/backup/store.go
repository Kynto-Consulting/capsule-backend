package backup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	// partSize bounds memory per upload (one part buffered at a time). S3 allows 10000
	// parts, so the largest single object is ~80 GB.
	partSize = 8 << 20

	metaDEK = "capsule-dek"
	metaVer = "capsule-enc"
	metaEnc = "aes-256-gcm-stream-v1"
)

type ObjectInfo struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// Store is the object storage the service writes to.
type Store interface {
	// Upload streams r to key (multipart when larger than one part) and returns the stored size.
	// When r fails mid-way the multipart upload is aborted and nothing is created.
	Upload(ctx context.Context, key string, meta map[string]string, r io.Reader) (int64, error)
	Download(ctx context.Context, key string) (io.ReadCloser, map[string]string, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]ObjectInfo, error)
}

// S3API is the subset of *s3.Client used here (so tests can fake it).
type S3API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	CreateMultipartUpload(context.Context, *s3.CreateMultipartUploadInput, ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error)
	UploadPart(context.Context, *s3.UploadPartInput, ...func(*s3.Options)) (*s3.UploadPartOutput, error)
	CompleteMultipartUpload(context.Context, *s3.CompleteMultipartUploadInput, ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(context.Context, *s3.AbortMultipartUploadInput, ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	ListObjectsV2(context.Context, *s3.ListObjectsV2Input, ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

type S3Store struct {
	api    S3API
	bucket string
	part   int
}

func NewS3Store(api S3API, bucket string) *S3Store {
	return &S3Store{api: api, bucket: bucket, part: partSize}
}

func (s *S3Store) Upload(ctx context.Context, key string, meta map[string]string, r io.Reader) (int64, error) {
	buf := make([]byte, s.part)
	n, err := io.ReadFull(r, buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF { // fits in one part
		_, perr := s.api.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &s.bucket, Key: &key, Body: bytes.NewReader(buf[:n]),
			Metadata: meta, ServerSideEncryption: s3types.ServerSideEncryptionAes256,
		})
		if perr != nil {
			return 0, fmt.Errorf("uploading backup: %w", perr)
		}
		return int64(n), nil
	}
	if err != nil {
		return 0, err
	}
	mu, err := s.api.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &s.bucket, Key: &key, Metadata: meta, ServerSideEncryption: s3types.ServerSideEncryptionAes256,
	})
	if err != nil {
		return 0, fmt.Errorf("starting multipart upload: %w", err)
	}
	abort := func() {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, _ = s.api.AbortMultipartUpload(actx, &s3.AbortMultipartUploadInput{Bucket: &s.bucket, Key: &key, UploadId: mu.UploadId})
	}
	var parts []s3types.CompletedPart
	var total int64
	for num := int32(1); ; num++ {
		out, uerr := s.api.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: &s.bucket, Key: &key, UploadId: mu.UploadId, PartNumber: aws.Int32(num),
			Body: bytes.NewReader(buf[:n]),
		})
		if uerr != nil {
			abort()
			return 0, fmt.Errorf("uploading part %d: %w", num, uerr)
		}
		parts = append(parts, s3types.CompletedPart{ETag: out.ETag, PartNumber: aws.Int32(num)})
		total += int64(n)
		if err != nil { // previous read was the short last part
			break
		}
		n, err = io.ReadFull(r, buf)
		if err == io.EOF { // nothing left
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			abort()
			return 0, err
		}
	}
	if _, cerr := s.api.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: &s.bucket, Key: &key, UploadId: mu.UploadId,
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: parts},
	}); cerr != nil {
		abort()
		return 0, fmt.Errorf("completing multipart upload: %w", cerr)
	}
	return total, nil
}

func (s *S3Store) Download(ctx context.Context, key string) (io.ReadCloser, map[string]string, error) {
	out, err := s.api.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &key})
	if err != nil {
		return nil, nil, fmt.Errorf("downloading backup: %w", err)
	}
	return out.Body, out.Metadata, nil
}

func (s *S3Store) Delete(ctx context.Context, key string) error {
	_, err := s.api.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &key})
	return err
}

func (s *S3Store) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	var out []ObjectInfo
	var token *string
	for {
		res, err := s.api.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &s.bucket, Prefix: &prefix, ContinuationToken: token})
		if err != nil {
			return nil, err
		}
		for _, o := range res.Contents {
			oi := ObjectInfo{Key: aws.ToString(o.Key), Size: aws.ToInt64(o.Size)}
			if o.LastModified != nil {
				oi.LastModified = *o.LastModified
			}
			out = append(out, oi)
		}
		if !aws.ToBool(res.IsTruncated) || res.NextContinuationToken == nil {
			return out, nil
		}
		token = res.NextContinuationToken
	}
}

var errNoMeta = errors.New("backup object has no encryption metadata")

// openObject downloads key and returns a plaintext reader.
func openObject(ctx context.Context, st Store, secret, key string) (io.ReadCloser, io.Reader, error) {
	body, meta, err := st.Download(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	wrapped := metaLookup(meta, metaDEK)
	if wrapped == "" {
		body.Close()
		return nil, nil, errNoMeta
	}
	dek, err := UnwrapDEK(wrapped, secret)
	if err != nil {
		body.Close()
		return nil, nil, err
	}
	return body, NewDecryptReader(body, dek), nil
}

// metaLookup is case-insensitive (S3 lower-cases user metadata keys).
func metaLookup(m map[string]string, k string) string {
	for mk, v := range m {
		if len(mk) == len(k) && equalFold(mk, k) {
			return v
		}
	}
	return ""
}

func equalFold(a, b string) bool {
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 32
		}
		if 'A' <= y && y <= 'Z' {
			y += 32
		}
		if x != y {
			return false
		}
	}
	return true
}
