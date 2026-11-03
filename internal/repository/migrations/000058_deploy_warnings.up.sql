-- Deploy connection audit: non-routed internal connections found at deploy time.
-- connection_warnings holds findings only (variable NAME / file:line, sanitised endpoint): never secret values.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS connection_warnings jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE projects    ADD COLUMN IF NOT EXISTS connection_audit_mode varchar(10) NOT NULL DEFAULT 'warn';

CREATE TABLE IF NOT EXISTS connection_audit_suppressions (
    project_id  uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    finding_id  varchar(64)  NOT NULL,
    reason      text         NOT NULL,
    expires_at  timestamptz,
    created_by  text         NOT NULL DEFAULT '',
    created_at  timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, finding_id)
);
