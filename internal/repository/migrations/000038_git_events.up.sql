-- Git Capsule A5: ledger de eventos de producto (entrantes de Forgejo y propios de Capsule).
-- Un delivery entrante de Forgejo se registra una sola vez (idempotencia por X-Forgejo-Delivery).
CREATE TABLE IF NOT EXISTS git_events (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id        uuid        NOT NULL REFERENCES projects(id)      ON DELETE CASCADE,
    source            varchar(10) NOT NULL DEFAULT 'capsule',
    delivery_id       text        NOT NULL DEFAULT '',
    raw_event         varchar(60) NOT NULL DEFAULT '',
    event             varchar(60) NOT NULL,
    actor             text        NOT NULL DEFAULT '',
    actor_user_id     uuid,
    branch            text        NOT NULL DEFAULT '',
    data              jsonb       NOT NULL DEFAULT '{}',
    recipients        uuid[]      NOT NULL DEFAULT '{}',
    dispatched_at     timestamptz,
    dispatch_attempts int         NOT NULL DEFAULT 0,
    created_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_git_events_source CHECK (source IN ('forgejo', 'capsule'))
);
-- Idempotencia: el mismo delivery de un proyecto entra una sola vez.
CREATE UNIQUE INDEX IF NOT EXISTS uq_git_events_delivery ON git_events(project_id, delivery_id) WHERE delivery_id <> '';
CREATE INDEX IF NOT EXISTS idx_git_events_project_time ON git_events(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_git_events_undispatched ON git_events(created_at) WHERE dispatched_at IS NULL;

-- Rotacion del secreto del webhook ENTRANTE (project_git.webhook_secret_enc): el secreto anterior
-- se sigue aceptando 24 h (SPEC 6.2). Un trigger lo guarda al cambiar el secreto para no tocar el
-- codigo de rotacion de otros paquetes. Si el cifrado cambia con el mismo secreto (Put repetido) la
-- fila previa queda con el mismo valor: inofensivo.
CREATE TABLE IF NOT EXISTS git_webhook_previous_secrets (
    project_id uuid        PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    secret_enc bytea       NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE OR REPLACE FUNCTION git_remember_previous_webhook_secret() RETURNS trigger AS $$
BEGIN
    IF OLD.webhook_secret_enc IS NOT NULL AND NEW.webhook_secret_enc IS DISTINCT FROM OLD.webhook_secret_enc THEN
        INSERT INTO git_webhook_previous_secrets (project_id, secret_enc, expires_at)
        VALUES (OLD.project_id, OLD.webhook_secret_enc, now() + interval '24 hours')
        ON CONFLICT (project_id) DO UPDATE SET secret_enc = EXCLUDED.secret_enc, expires_at = EXCLUDED.expires_at;
    END IF;
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_project_git_previous_secret ON project_git;
CREATE TRIGGER trg_project_git_previous_secret
    AFTER UPDATE OF webhook_secret_enc ON project_git
    FOR EACH ROW EXECUTE FUNCTION git_remember_previous_webhook_secret();
