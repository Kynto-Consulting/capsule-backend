-- Git Capsule B7: estado de Renovate por repo (activacion, onboarding, PR abiertos, ultima ejecucion).
CREATE TABLE IF NOT EXISTS renovate_state (
    project_id          uuid          PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    enabled             boolean       NOT NULL DEFAULT false,
    preset              varchar(255)  NOT NULL DEFAULT '',
    schedule            varchar(255)  NOT NULL DEFAULT '',
    onboarding          varchar(12)   NOT NULL DEFAULT 'none',
    open_prs            int           NOT NULL DEFAULT 0,
    last_run_at         timestamptz,
    last_run_status     varchar(12)   NOT NULL DEFAULT '',
    dashboard_issue_url varchar(512)  NOT NULL DEFAULT '',
    topic_synced        boolean       NOT NULL DEFAULT false,
    sync_error          varchar(300)  NOT NULL DEFAULT '',
    last_sync_at        timestamptz,
    updated_by          uuid          REFERENCES users(id) ON DELETE SET NULL,
    updated_at          timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT chk_renovate_onboarding CHECK (onboarding IN ('none','pr_open','merged'))
);
CREATE INDEX IF NOT EXISTS idx_renovate_enabled ON renovate_state(enabled) WHERE enabled = true;
