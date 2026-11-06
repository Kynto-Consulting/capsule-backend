package aimm

import (
	"bytes"
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3API is the S3 surface the stage uses.
type S3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, o ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, o ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// S3Stage keeps uploaded audio under the "ai-stage/" prefix of an AWS bucket until the transcription ends; Transcribe reads it from there.
// The bucket needs a lifecycle rule that expires the prefix after 1 day, as a safety net for jobs that never finish being polled.
type S3Stage struct {
	API    S3API
	Bucket string
}

// Put uploads the object and returns its s3:// URI.
func (s *S3Stage) Put(ctx context.Context, key string, data []byte, contentType string) (string, error) {
	_, err := s.API.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key), Body: bytes.NewReader(data), ContentType: aws.String(contentType)})
	if err != nil {
		return "", err
	}
	return "s3://" + s.Bucket + "/" + key, nil
}

// Delete removes the staged object.
func (s *S3Stage) Delete(ctx context.Context, key string) error {
	_, err := s.API.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.Bucket), Key: aws.String(key)})
	return err
}
