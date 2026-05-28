BEGIN;

ALTER TABLE databases ADD COLUMN IF NOT EXISTS org_id uuid REFERENCES organizations(id);

-- Backfill org_id from project
UPDATE databases d
SET org_id = p.org_id
FROM projects p
WHERE d.project_id = p.id AND d.org_id IS NULL;

-- Now make project_id nullable and org_id required
ALTER TABLE databases ALTER COLUMN project_id DROP NOT NULL;
ALTER TABLE databases ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_databases_org ON databases(org_id) WHERE deleted_at IS NULL;

COMMIT;
