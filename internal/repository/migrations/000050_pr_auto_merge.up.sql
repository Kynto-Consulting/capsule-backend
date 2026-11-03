-- Git Capsule B8: auto-merge de PR gestionado por Capsule (un worker reintenta el merge por eventos).
-- Una fila por PR; volver a armar la reemplaza. El estado de borrador NO tiene tabla: Forgejo lo
-- representa con el prefijo "WIP:" del titulo (verificado por A1). CODEOWNERS se lee de la rama base
-- (cache en memoria de segundos), por eso tampoco hay codeowners_cache.
CREATE TABLE IF NOT EXISTS pr_auto_merge (
    project_id      uuid        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    pr_number       int         NOT NULL,
    head_sha        varchar(64) NOT NULL,
    merge_style     varchar(16) NOT NULL,
    merge_title     text        NOT NULL DEFAULT '',
    merge_message   text        NOT NULL DEFAULT '',
    delete_branch   boolean     NOT NULL DEFAULT false,
    requested_by    uuid        REFERENCES users(id) ON DELETE SET NULL,
    requested_login varchar(64) NOT NULL DEFAULT '',
    state           varchar(12) NOT NULL DEFAULT 'armed',
    reason          text        NOT NULL DEFAULT '',
    attempts        int         NOT NULL DEFAULT 0,
    last_attempt_at timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    claimed_until   timestamptz,
    last_error      text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, pr_number),
    CONSTRAINT chk_pr_auto_merge_state CHECK (state IN ('armed','merging','merged','cancelled')),
    CONSTRAINT chk_pr_auto_merge_style CHECK (merge_style IN ('merge','squash','rebase','fast-forward')),
    CONSTRAINT chk_pr_auto_merge_pr CHECK (pr_number > 0)
);
CREATE INDEX IF NOT EXISTS idx_pr_auto_merge_due ON pr_auto_merge(next_attempt_at) WHERE state IN ('armed','merging');
CREATE INDEX IF NOT EXISTS idx_pr_auto_merge_head ON pr_auto_merge(project_id, head_sha) WHERE state = 'armed';
