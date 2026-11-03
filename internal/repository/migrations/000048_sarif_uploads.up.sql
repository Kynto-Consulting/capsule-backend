-- Git Capsule B7: subidas SARIF (procesamiento asincrono) y estado del check capsule/security por SHA.
-- findings guarda las alertas ya normalizadas y SIN el valor de los secretos (se vacia al terminar).
-- El SARIF original no se persiste.
CREATE TABLE IF NOT EXISTS sarif_uploads (
    id               uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id       uuid          NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    commit_sha       varchar(64)   NOT NULL,
    ref              varchar(255)  NOT NULL,
    branch           varchar(255)  NOT NULL,
    pr               int,
    tool             varchar(20)   NOT NULL,
    tool_name        varchar(64)   NOT NULL,
    status           varchar(12)   NOT NULL DEFAULT 'pending',
    error            varchar(500)  NOT NULL DEFAULT '',
    idempotency_key  varchar(128),
    results_total    int           NOT NULL DEFAULT 0,
    alerts_created   int           NOT NULL DEFAULT 0,
    alerts_fixed     int           NOT NULL DEFAULT 0,
    superseded       boolean       NOT NULL DEFAULT false,
    findings         jsonb,
    attempts         int           NOT NULL DEFAULT 0,
    created_by       uuid          REFERENCES users(id) ON DELETE SET NULL,
    created_at       timestamptz   NOT NULL DEFAULT now(),
    started_at       timestamptz,
    completed_at     timestamptz,
    CONSTRAINT chk_sarif_status CHECK (status IN ('pending','processing','complete','failed'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_sarif_idem ON sarif_uploads(project_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sarif_pending ON sarif_uploads(status, created_at) WHERE status IN ('pending','processing');
CREATE INDEX IF NOT EXISTS idx_sarif_scope ON sarif_uploads(project_id, branch, tool_name, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sarif_commit ON sarif_uploads(project_id, commit_sha, status);

CREATE TABLE IF NOT EXISTS security_check_runs (
    project_id      uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    head_sha        varchar(64)  NOT NULL,
    pr_number       int          NOT NULL DEFAULT 0,
    base_branch     varchar(255) NOT NULL DEFAULT '',
    head_branch     varchar(255) NOT NULL DEFAULT '',
    state           varchar(10)  NOT NULL DEFAULT 'pending',
    description     varchar(255) NOT NULL DEFAULT '',
    first_seen_at   timestamptz  NOT NULL DEFAULT now(),
    last_eval_at    timestamptz,
    final           boolean      NOT NULL DEFAULT false,
    PRIMARY KEY (project_id, head_sha),
    CONSTRAINT chk_seccheck_state CHECK (state IN ('pending','success','failure','error'))
);
CREATE INDEX IF NOT EXISTS idx_seccheck_open ON security_check_runs(final, first_seen_at) WHERE final = false;
