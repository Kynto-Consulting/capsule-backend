DELETE FROM gateway_services WHERE project_port_id IS NOT NULL OR database_id IS NOT NULL;
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS ck_organizations_gateway_policy;
ALTER TABLE organizations DROP COLUMN IF EXISTS gateway_policy;
