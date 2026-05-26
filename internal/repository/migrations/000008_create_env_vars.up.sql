BEGIN;

CREATE TABLE env_vars (
    id         uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid         NOT NULL REFERENCES projects(id),
    key        varchar(255) NOT NULL,
    value_enc  bytea        NOT NULL,
    is_secret  boolean      NOT NULL DEFAULT true,
    scope      varchar(30)  NOT NULL DEFAULT 'runtime',
    created_at timestamptz  NOT NULL DEFAULT now(),
    updated_at timestamptz  NOT NULL DEFAULT now(),

    CONSTRAINT uq_env_vars_project_key UNIQUE (project_id, key)
);

CREATE INDEX idx_env_vars_project ON env_vars(project_id);

COMMIT;
