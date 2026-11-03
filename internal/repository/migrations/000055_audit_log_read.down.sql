DROP INDEX IF EXISTS idx_audit_created;
DROP INDEX IF EXISTS idx_audit_org_user_cursor;
DROP INDEX IF EXISTS idx_audit_org_action_cursor;
DROP INDEX IF EXISTS idx_audit_org_project_cursor;
DROP INDEX IF EXISTS idx_audit_org_cursor;
ALTER TABLE audit_logs DROP COLUMN IF EXISTS actor_label;
ALTER TABLE audit_logs DROP COLUMN IF EXISTS project_id;
