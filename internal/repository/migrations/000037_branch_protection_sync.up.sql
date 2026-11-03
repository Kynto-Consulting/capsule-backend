-- Git Capsule A4: estado de proyeccion de cada regla a Forgejo (una fila por regla).
-- status: pending (aun no proyectada), synced, error. stale_rule_names son nombres de regla que
-- quedaron en Forgejo tras renombrar el patron y que hay que borrar.
CREATE TABLE IF NOT EXISTS branch_protection_sync (
    rule_id           uuid         PRIMARY KEY REFERENCES branch_protection_rules(id) ON DELETE CASCADE,
    project_id        uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status            varchar(10)  NOT NULL DEFAULT 'pending',
    forgejo_rule_name varchar(255) NOT NULL DEFAULT '',
    stale_rule_names  text[]       NOT NULL DEFAULT '{}',
    spec_hash         varchar(64)  NOT NULL DEFAULT '',
    attempts          int          NOT NULL DEFAULT 0,
    last_error        text         NOT NULL DEFAULT '',
    last_synced_at    timestamptz,
    last_drift_at     timestamptz,
    drift_count       int          NOT NULL DEFAULT 0,
    updated_at        timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_branch_protection_sync_status CHECK (status IN ('pending', 'synced', 'error'))
);
CREATE INDEX IF NOT EXISTS idx_branch_protection_sync_project ON branch_protection_sync(project_id);
