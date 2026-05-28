BEGIN;

ALTER TABLE domains ADD COLUMN IF NOT EXISTS org_id uuid REFERENCES organizations(id);

UPDATE domains d
SET org_id = p.org_id
FROM projects p
WHERE d.project_id = p.id AND d.org_id IS NULL;

ALTER TABLE domains ALTER COLUMN project_id DROP NOT NULL;
ALTER TABLE domains ALTER COLUMN org_id SET NOT NULL;

CREATE INDEX idx_domains_org ON domains(org_id);

COMMIT;
