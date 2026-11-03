-- Git Capsule C2: actividad por repo (fuente de la linea de actividad y de los insights) y
-- estado del resumen (digest) de notificaciones.
CREATE TABLE IF NOT EXISTS git_activity (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id    uuid        NOT NULL REFERENCES projects(id)      ON DELETE CASCADE,
    -- git_events.id que lo origino; sin FK para que la retencion de eventos no lo arrastre.
    event_id      uuid,
    type          varchar(60) NOT NULL,
    actor         text        NOT NULL DEFAULT '',
    actor_user_id uuid,
    ref           text        NOT NULL DEFAULT '',
    summary       text        NOT NULL DEFAULT '',
    branch        text        NOT NULL DEFAULT '',
    pr            int         NOT NULL DEFAULT 0,
    data          jsonb       NOT NULL DEFAULT '{}',
    occurred_at   timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
-- Un evento produce una sola fila (el fan-out puede repetirse).
CREATE UNIQUE INDEX IF NOT EXISTS uq_git_activity_event ON git_activity(event_id) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_git_activity_cursor ON git_activity(project_id, occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_git_activity_type ON git_activity(project_id, type, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_git_activity_pr ON git_activity(project_id, pr) WHERE pr > 0;
CREATE INDEX IF NOT EXISTS idx_git_activity_retention ON git_activity(occurred_at);

-- Ultimo resumen enviado por usuario (envio como maximo una vez por periodo, aunque haya varias instancias).
CREATE TABLE IF NOT EXISTS notification_digest_state (
    user_id      uuid        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    last_sent_at timestamptz NOT NULL
);
