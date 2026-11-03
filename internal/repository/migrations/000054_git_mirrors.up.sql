-- Git Capsule C1: espejo push hacia un tercero (T17). La credencial se guarda cifrada (AES-GCM con la
-- clave de la plataforma, como los secretos de webhooks); remote_url nunca lleva credenciales.
CREATE TABLE IF NOT EXISTS git_mirrors (
    project_id          uuid         PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    org_id              uuid         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    remote_url          text         NOT NULL,
    branches            text[]       NOT NULL DEFAULT '{}',
    sync_interval       varchar(10)  NOT NULL DEFAULT 'daily',
    credential_enc      bytea,
    forgejo_remote_name varchar(100) NOT NULL DEFAULT '',
    last_sync_at        timestamptz,
    last_error          text         NOT NULL DEFAULT '',
    syncing_since       timestamptz,
    created_by          uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at          timestamptz  NOT NULL DEFAULT now(),
    updated_at          timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_git_mirrors_interval CHECK (sync_interval IN ('on_push', 'hourly', 'daily'))
);
CREATE INDEX IF NOT EXISTS idx_git_mirrors_org ON git_mirrors(org_id);
