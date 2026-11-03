-- Per-project data backups (database dumps, volumes, manifests) and platform backups.
CREATE TABLE IF NOT EXISTS backup_settings (
    project_id        uuid        PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    enabled           boolean     NOT NULL DEFAULT true,
    schedule          varchar(10) NOT NULL DEFAULT 'daily',
    retention_days    int         NOT NULL DEFAULT 14,
    include_databases boolean     NOT NULL DEFAULT true,
    include_volumes   boolean     NOT NULL DEFAULT false,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_backup_schedule CHECK (schedule IN ('hourly', '6h', '12h', 'daily', 'weekly')),
    CONSTRAINT chk_backup_retention CHECK (retention_days >= 1)
);

-- project_id NULL = platform-level run (server files + inventory).
CREATE TABLE IF NOT EXISTS backup_runs (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  uuid        REFERENCES projects(id) ON DELETE CASCADE,
    org_id      uuid        REFERENCES organizations(id) ON DELETE CASCADE,
    kind        varchar(10) NOT NULL DEFAULT 'backup',
    trigger     varchar(10) NOT NULL DEFAULT 'manual',
    status      varchar(10) NOT NULL DEFAULT 'running',
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    size_bytes  bigint      NOT NULL DEFAULT 0,
    error       text        NOT NULL DEFAULT '',
    created_by  uuid        REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT chk_backup_runs_kind   CHECK (kind IN ('backup', 'restore', 'verify')),
    CONSTRAINT chk_backup_runs_status CHECK (status IN ('running', 'success', 'failed'))
);
-- One running job per project (and one for the platform) at a time.
CREATE UNIQUE INDEX IF NOT EXISTS uq_backup_runs_running
    ON backup_runs ((COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid)))
    WHERE status = 'running';
CREATE INDEX IF NOT EXISTS idx_backup_runs_project ON backup_runs(project_id, started_at DESC);

CREATE TABLE IF NOT EXISTS backup_snapshots (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id     uuid        REFERENCES projects(id) ON DELETE CASCADE,
    run_id         uuid        NOT NULL REFERENCES backup_runs(id) ON DELETE CASCADE,
    kind           varchar(10) NOT NULL,
    source         varchar(200) NOT NULL,
    source_id      varchar(100) NOT NULL DEFAULT '',
    engine         varchar(30) NOT NULL DEFAULT '',
    object_key     text        NOT NULL,
    size_bytes     bigint      NOT NULL DEFAULT 0,
    checksum       varchar(64) NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    deleted_at     timestamptz,
    CONSTRAINT chk_backup_snapshots_kind CHECK (kind IN ('database', 'volume', 'manifest', 'platform'))
);
CREATE INDEX IF NOT EXISTS idx_backup_snapshots_project ON backup_snapshots(project_id, created_at DESC) WHERE deleted_at IS NULL;
