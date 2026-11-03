ALTER TABLE organizations DROP CONSTRAINT IF EXISTS chk_orgs_project_access_mode;
ALTER TABLE organizations DROP COLUMN IF EXISTS project_access_mode;
DROP TABLE IF EXISTS project_members;
