ALTER TABLE deployments
    DROP COLUMN IF EXISTS error_message,
    DROP COLUMN IF EXISTS health_detail,
    DROP COLUMN IF EXISTS health_checked_at,
    DROP COLUMN IF EXISTS health_path,
    DROP COLUMN IF EXISTS health_status;

ALTER TABLE projects
    DROP COLUMN IF EXISTS health_expected_status,
    DROP COLUMN IF EXISTS health_interval_seconds,
    DROP COLUMN IF EXISTS health_timeout_seconds,
    DROP COLUMN IF EXISTS health_path;
