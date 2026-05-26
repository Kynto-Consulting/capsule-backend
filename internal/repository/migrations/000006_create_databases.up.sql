BEGIN;

CREATE TABLE databases (
    id               uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id       uuid         NOT NULL REFERENCES projects(id),
    name             varchar(100) NOT NULL,
    engine           varchar(30)  NOT NULL DEFAULT 'postgres',
    version          varchar(20)  NOT NULL DEFAULT '16',
    host             varchar(255) NOT NULL,
    port             int          NOT NULL DEFAULT 5432,
    db_name          varchar(100) NOT NULL,
    credentials_enc  bytea        NOT NULL,
    status           varchar(30)  NOT NULL DEFAULT 'provisioning',
    size_mb          int          NOT NULL DEFAULT 0,
    container_id     varchar(100),
    volume_name      varchar(200),
    created_at       timestamptz  NOT NULL DEFAULT now(),
    updated_at       timestamptz  NOT NULL DEFAULT now(),
    deleted_at       timestamptz
);

CREATE TABLE redis_instances (
    id           uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   uuid         NOT NULL REFERENCES projects(id),
    name         varchar(100) NOT NULL,
    version      varchar(20)  NOT NULL DEFAULT '7',
    host         varchar(255) NOT NULL,
    port         int          NOT NULL DEFAULT 6379,
    password_enc bytea        NOT NULL,
    status       varchar(30)  NOT NULL DEFAULT 'provisioning',
    memory_mb    int          NOT NULL DEFAULT 256,
    container_id varchar(100),
    volume_name  varchar(200),
    created_at   timestamptz  NOT NULL DEFAULT now(),
    updated_at   timestamptz  NOT NULL DEFAULT now(),
    deleted_at   timestamptz
);

CREATE INDEX idx_databases_project ON databases(project_id)       WHERE deleted_at IS NULL;
CREATE INDEX idx_redis_project     ON redis_instances(project_id) WHERE deleted_at IS NULL;

COMMIT;
