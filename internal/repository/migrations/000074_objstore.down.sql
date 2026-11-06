DROP TABLE IF EXISTS objstore_quotas;
DROP TABLE IF EXISTS objstore_buckets;
DELETE FROM backup_snapshots WHERE kind = 'objects';
ALTER TABLE backup_snapshots DROP CONSTRAINT IF EXISTS chk_backup_snapshots_kind;
ALTER TABLE backup_snapshots ADD CONSTRAINT chk_backup_snapshots_kind
    CHECK (kind IN ('database', 'volume', 'manifest', 'platform'));
