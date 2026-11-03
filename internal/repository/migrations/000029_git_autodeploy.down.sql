DROP INDEX IF EXISTS idx_deployments_project_trigger_status;
DROP INDEX IF EXISTS uq_projects_preview_pr;
DROP INDEX IF EXISTS idx_projects_expires;
DROP INDEX IF EXISTS idx_projects_parent;
ALTER TABLE projects DROP COLUMN IF EXISTS preview_comment_id;
ALTER TABLE projects DROP COLUMN IF EXISTS expires_at;
ALTER TABLE projects DROP COLUMN IF EXISTS preview_pr;
ALTER TABLE projects DROP COLUMN IF EXISTS parent_project_id;
DROP TABLE IF EXISTS project_git;
