DROP TRIGGER IF EXISTS trg_project_git_previous_secret ON project_git;
DROP FUNCTION IF EXISTS git_remember_previous_webhook_secret();
DROP TABLE IF EXISTS git_webhook_previous_secrets;
DROP TABLE IF EXISTS git_events;
