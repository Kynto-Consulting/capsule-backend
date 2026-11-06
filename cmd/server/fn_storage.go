package main

import (
	"context"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/server"
)

// fnStorageResolver connects the `storage:<name>` scope of functions to Capsule's own object store: the run gets the S3
// access of that bucket. "endpoint" is the internal route (host.docker.internal, for containers on the work node) and
// "public_endpoint" the project's https://<slug>-storage.<zone> (path style), which is what a Lambda run uses: a Lambda is
// outside the host and cannot reach host.docker.internal. <name> is the bucket name or the name of the storage resource.
func fnStorageResolver(o *server.ObjstoreDeps, dbs domain.DatabaseRepository, projects domain.ProjectRepository) fn.StorageResolver {
	return func(ctx context.Context, projectID uuid.UUID, name string) (map[string]string, error) {
		recs, err := o.Repo.ListByProject(ctx, projectID)
		if err != nil {
			return nil, err
		}
		resources, _ := dbs.ListByProject(ctx, projectID)
		for _, r := range recs {
			match := r.Bucket == name
			for _, d := range resources {
				if d.ID == r.DatabaseID && d.Name == name {
					match = true
				}
			}
			if !match {
				continue
			}
			secret, err := o.Repo.Secret(r)
			if err != nil {
				return nil, err
			}
			kv := map[string]string{"endpoint": o.InternalEndpoint, "bucket": r.Bucket, "access_key_id": r.AccessKey, "secret_access_key": secret, "region": o.Region}
			if o.PublicEndpoint != nil {
				if p, err := projects.GetByID(ctx, projectID); err == nil && p.Slug != "" {
					kv["public_endpoint"] = o.PublicEndpoint(p.Slug)
				}
			}
			return kv, nil
		}
		return nil, fn.ErrNotFound
	}
}
