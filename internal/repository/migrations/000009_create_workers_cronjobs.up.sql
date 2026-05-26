BEGIN;

CREATE TABLE workers (
    id             uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id     uuid         NOT NULL REFERENCES projects(id),
    name           varchar(100) NOT NULL,
    command        text         NOT NULL,
    replicas       int          NOT NULL DEFAULT 1,
    status         varchar(30)  NOT NULL DEFAULT 'stopped',
    container_id   varchar(100),
    restart_policy varchar(30)  NOT NULL DEFAULT 'on-failure',
    created_at     timestamptz  NOT NULL DEFAULT now(),
    updated_at     timestamptz  NOT NULL DEFAULT now(),
    deleted_at     timestamptz
);

CREATE TABLE cronjobs (
    id              uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      uuid         NOT NULL REFERENCES projects(id),
    name            varchar(100) NOT NULL,
    schedule        varchar(100) NOT NULL,
    command         text         NOT NULL,
    timezone        varchar(50)  NOT NULL DEFAULT 'UTC',
    status          varchar(30)  NOT NULL DEFAULT 'active',
    last_run_status varchar(30),
    last_run_at     timestamptz,
    next_run_at     timestamptz,
    created_at      timestamptz  NOT NULL DEFAULT now(),
    updated_at      timestamptz  NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);

CREATE INDEX idx_workers_project   ON workers(project_id)  WHERE deleted_at IS NULL;
CREATE INDEX idx_cronjobs_project  ON cronjobs(project_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_cronjobs_next_run ON cronjobs(next_run_at) WHERE status = 'active';

COMMIT;
