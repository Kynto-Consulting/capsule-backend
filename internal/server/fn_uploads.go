package server

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/kynto/capsule/backend/internal/server/handlers"
)

// artifactsPresigner presigns uploads of function sources into the artifacts bucket: the same bucket and the same
// presigned PUT that `capsule deploy` uses for project sources (POST .../deployments/upload-url).
func artifactsPresigner(c *s3.Client, bucket string) handlers.UploadPresigner {
	ps := s3.NewPresignClient(c)
	return func(ctx context.Context, key string) (string, error) {
		out, err := ps.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key}, s3.WithPresignExpires(15*time.Minute))
		if err != nil {
			return "", err
		}
		return out.URL, nil
	}
}
