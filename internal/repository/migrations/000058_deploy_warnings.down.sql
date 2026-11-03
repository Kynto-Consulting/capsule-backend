DROP TABLE IF EXISTS connection_audit_suppressions;
ALTER TABLE projects    DROP COLUMN IF EXISTS connection_audit_mode;
ALTER TABLE deployments DROP COLUMN IF EXISTS connection_warnings;
