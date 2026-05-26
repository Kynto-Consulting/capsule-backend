BEGIN;

CREATE TABLE backup_history (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    resource_type    varchar(30) NOT NULL,
    resource_id      uuid,
    backup_type      varchar(30) NOT NULL,
    storage_path     text        NOT NULL,
    storage_backend  varchar(20) NOT NULL DEFAULT 's3',
    size_bytes       bigint,
    checksum_sha256  varchar(64),
    encrypted        boolean     NOT NULL DEFAULT true,
    status           varchar(30) NOT NULL DEFAULT 'in_progress',
    initiated_by     uuid        REFERENCES users(id),
    started_at       timestamptz,
    completed_at     timestamptz,
    expires_at       timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_logs (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid        REFERENCES users(id),
    org_id        uuid        REFERENCES organizations(id),
    action        varchar(50) NOT NULL,
    resource_type varchar(50) NOT NULL,
    resource_id   uuid,
    ip_address    inet,
    user_agent    text,
    old_values    jsonb,
    new_values    jsonb,
    metadata      jsonb       NOT NULL DEFAULT '{}',
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_tokens (
    id           uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid         NOT NULL REFERENCES users(id),
    name         varchar(100) NOT NULL,
    token_hash   varchar(255) NOT NULL,
    prefix       varchar(10)  NOT NULL,
    scopes       text         NOT NULL DEFAULT '*',
    last_used_at timestamptz,
    expires_at   timestamptz,
    created_at   timestamptz  NOT NULL DEFAULT now(),
    revoked_at   timestamptz,

    CONSTRAINT uq_api_tokens_hash UNIQUE (token_hash)
);

CREATE INDEX idx_backups_resource ON backup_history(resource_type, resource_id);
CREATE INDEX idx_backups_status   ON backup_history(status);
CREATE INDEX idx_backups_created  ON backup_history(created_at DESC);

CREATE INDEX idx_audit_user     ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_org      ON audit_logs(org_id, created_at DESC);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_action   ON audit_logs(action, created_at DESC);

CREATE INDEX idx_tokens_user   ON api_tokens(user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_tokens_prefix ON api_tokens(prefix);

COMMIT;
