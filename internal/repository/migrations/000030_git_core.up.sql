-- Git del nucleo (Forgejo): estado de provision por proyecto y sincronizacion de equipos pendiente.
CREATE TABLE IF NOT EXISTS git_core_state (
    project_id      uuid        PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    status          varchar(12) NOT NULL DEFAULT 'pending',
    attempts        int         NOT NULL DEFAULT 0,
    last_error      text        NOT NULL DEFAULT '',
    import_url      text        NOT NULL DEFAULT '',
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_git_core_state_status CHECK (status IN ('pending', 'ready', 'failed'))
);
CREATE INDEX IF NOT EXISTS idx_git_core_state_due ON git_core_state(next_attempt_at) WHERE status = 'pending';

-- Usuarios con rol en un proyecto que aun no existen en Forgejo (aparecen en su primer login OIDC).
CREATE TABLE IF NOT EXISTS git_team_sync (
    project_id      uuid        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id         uuid        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    attempts        int         NOT NULL DEFAULT 0,
    last_error      text        NOT NULL DEFAULT '',
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_git_team_sync_due ON git_team_sync(next_attempt_at);
