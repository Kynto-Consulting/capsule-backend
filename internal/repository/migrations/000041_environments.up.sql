-- Git Capsule A6: entornos de despliegue (politica con nombre sobre un proyecto/repo). SPEC 5.7.
-- target_project_id es el proyecto Capsule que recibe el despliegue (puede ser el mismo).
CREATE TABLE IF NOT EXISTS environments (
    id                          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id                  uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name                        varchar(31)  NOT NULL,
    kind                        varchar(16)  NOT NULL DEFAULT 'other',
    target_project_id           uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    branch_patterns             text[]       NOT NULL DEFAULT '{}',
    tag_patterns                text[]       NOT NULL DEFAULT '{}',
    auto_deploy                 boolean      NOT NULL DEFAULT false,
    reviewers                   jsonb        NOT NULL DEFAULT '[]'::jsonb,
    required_approvals          int          NOT NULL DEFAULT 0,
    allow_self_approval         boolean      NOT NULL DEFAULT false,
    wait_minutes                int          NOT NULL DEFAULT 0,
    windows                     jsonb        NOT NULL DEFAULT '[]'::jsonb,
    require_checks_on_sha       boolean      NOT NULL DEFAULT true,
    require_source_environment  varchar(31)  NOT NULL DEFAULT '',
    require_security_policy     boolean      NOT NULL DEFAULT false,
    rollback_requires_approval  boolean      NOT NULL DEFAULT false,
    created_by                  uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at                  timestamptz  NOT NULL DEFAULT now(),
    updated_at                  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_environments_name UNIQUE (project_id, name),
    CONSTRAINT chk_environments_kind CHECK (kind IN ('staging', 'production', 'other')),
    CONSTRAINT chk_environments_approvals CHECK (required_approvals BETWEEN 0 AND 5),
    CONSTRAINT chk_environments_wait CHECK (wait_minutes BETWEEN 0 AND 43200)
);
CREATE INDEX IF NOT EXISTS idx_environments_target ON environments(target_project_id);
