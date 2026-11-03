-- Deploy health checks + failure reason.
-- Per-project health settings (empty health_path = HTTP check disabled; the
-- worker then only verifies the container stays up for a minimum time).
ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS health_path             text    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS health_timeout_seconds  integer NOT NULL DEFAULT 60,
    ADD COLUMN IF NOT EXISTS health_interval_seconds integer NOT NULL DEFAULT 3,
    ADD COLUMN IF NOT EXISTS health_expected_status  text    NOT NULL DEFAULT '200-399';

-- Per-deployment health result and failure reason.
ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS health_status     text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS health_path       text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS health_checked_at timestamptz,
    ADD COLUMN IF NOT EXISTS health_detail     text        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS error_message     text        NOT NULL DEFAULT '';
