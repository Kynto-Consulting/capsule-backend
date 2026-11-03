-- Git Capsule C3: journal of total/partial recoveries (docs/git-capsule/DR-BACKUP.md section 5).
-- steps is the per-step journal (same JSON as the bootstrap file journal), so a run can be resumed.
CREATE TABLE IF NOT EXISTS recovery_runs (
    id               uuid         PRIMARY KEY,
    mode             varchar(10)  NOT NULL,
    status           varchar(10)  NOT NULL DEFAULT 'planned',
    project_id       uuid         REFERENCES projects(id) ON DELETE SET NULL,
    requested_by     uuid         REFERENCES users(id) ON DELETE SET NULL,
    idempotency_key  varchar(100),
    plan_id          char(64)     NOT NULL DEFAULT '',
    request          jsonb        NOT NULL DEFAULT '{}'::jsonb,
    steps            jsonb        NOT NULL DEFAULT '[]'::jsonb,
    report_key       text         NOT NULL DEFAULT '',
    error            text         NOT NULL DEFAULT '',
    started_at       timestamptz  NOT NULL DEFAULT now(),
    finished_at      timestamptz,
    CONSTRAINT chk_recovery_runs_mode   CHECK (mode IN ('plan', 'apply', 'verify')),
    CONSTRAINT chk_recovery_runs_status CHECK (status IN ('planned', 'running', 'success', 'failed', 'partial'))
);
-- One apply at a time (like uq_backup_runs_running of 000032).
CREATE UNIQUE INDEX IF NOT EXISTS uq_recovery_runs_active
    ON recovery_runs ((true)) WHERE status = 'running' AND mode = 'apply';
CREATE UNIQUE INDEX IF NOT EXISTS uq_recovery_runs_idem
    ON recovery_runs (idempotency_key, COALESCE(requested_by, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_recovery_runs_started ON recovery_runs(started_at DESC);
