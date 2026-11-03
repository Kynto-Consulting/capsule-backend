-- Git Capsule A2: estado observado de los equipos de Forgejo por proyecto y rol (viewer/deployer/admin).
-- Una fila por (proyecto, rol); la escribe la reconciliacion. drift_* cuenta correcciones hechas
-- en pasadas periodicas/manuales (miembros añadidos o quitados a mano en Forgejo).
CREATE TABLE IF NOT EXISTS git_team_state (
    project_id        uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    role              varchar(10)  NOT NULL,
    team_id           bigint       NOT NULL,
    team_name         varchar(100) NOT NULL,
    permission        varchar(8)   NOT NULL,
    members           int          NOT NULL DEFAULT 0,
    last_synced_at    timestamptz  NOT NULL DEFAULT now(),
    last_error        text         NOT NULL DEFAULT '',
    drift_events      bigint       NOT NULL DEFAULT 0,
    last_drift_at     timestamptz,
    last_drift_added  int          NOT NULL DEFAULT 0,
    last_drift_removed int         NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, role),
    CONSTRAINT chk_git_team_state_role CHECK (role IN ('viewer', 'deployer', 'admin'))
);
CREATE INDEX IF NOT EXISTS idx_git_team_state_drift ON git_team_state (last_drift_at) WHERE last_drift_at IS NOT NULL;
