BEGIN;

CREATE TABLE projects (
    id             uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         uuid         NOT NULL REFERENCES organizations(id),
    name           varchar(100) NOT NULL,
    slug           varchar(100) NOT NULL,
    repo_url       text,
    branch         varchar(100) NOT NULL DEFAULT 'main',
    build_strategy varchar(30)  NOT NULL DEFAULT 'auto',
    runtime        varchar(30),
    serverless     boolean      NOT NULL DEFAULT false,
    replicas       int          NOT NULL DEFAULT 1,
    status         varchar(30)  NOT NULL DEFAULT 'created',
    labels         jsonb        NOT NULL DEFAULT '{}',
    created_at     timestamptz  NOT NULL DEFAULT now(),
    updated_at     timestamptz  NOT NULL DEFAULT now(),
    deleted_at     timestamptz,

    CONSTRAINT uq_projects_org_slug UNIQUE (org_id, slug) DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX idx_projects_org        ON projects(org_id)        WHERE deleted_at IS NULL;
CREATE INDEX idx_projects_org_slug   ON projects(org_id, slug)  WHERE deleted_at IS NULL;
CREATE INDEX idx_projects_status     ON projects(status)        WHERE deleted_at IS NULL;

COMMIT;
