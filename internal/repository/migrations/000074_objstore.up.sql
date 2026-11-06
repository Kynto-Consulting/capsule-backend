-- Capsule's own object store (internal/objstore). A bucket is a `databases` row with engine 'objstore';
-- this table holds what the S3 server needs: the global bucket name, public-read flag, the per-bucket
-- access key (secret encrypted like every other credential) and an optional per-bucket cap.
CREATE TABLE IF NOT EXISTS objstore_buckets (
    database_id uuid         PRIMARY KEY REFERENCES databases(id) ON DELETE CASCADE,
    org_id      uuid         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id  uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    bucket      varchar(63)  NOT NULL UNIQUE,
    public_read boolean      NOT NULL DEFAULT false,
    access_key  varchar(40)  NOT NULL UNIQUE,
    secret_enc  bytea        NOT NULL,
    max_bytes   bigint       CHECK (max_bytes IS NULL OR max_bytes > 0),
    created_at  timestamptz  NOT NULL DEFAULT now(),
    rotated_at  timestamptz
);
CREATE INDEX IF NOT EXISTS idx_objstore_buckets_project ON objstore_buckets(project_id);
CREATE INDEX IF NOT EXISTS idx_objstore_buckets_org ON objstore_buckets(org_id);

-- Size caps. scope 'project' or 'org'; a missing row means the platform default (CAPSULE_OBJSTORE_DEFAULT_*).
CREATE TABLE IF NOT EXISTS objstore_quotas (
    scope      varchar(8)  NOT NULL CHECK (scope IN ('org', 'project')),
    scope_id   uuid        NOT NULL,
    max_bytes  bigint      NOT NULL CHECK (max_bytes > 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, scope_id)
);

ALTER TABLE backup_snapshots DROP CONSTRAINT IF EXISTS chk_backup_snapshots_kind;
ALTER TABLE backup_snapshots ADD CONSTRAINT chk_backup_snapshots_kind
    CHECK (kind IN ('database', 'volume', 'manifest', 'platform', 'objects'));
