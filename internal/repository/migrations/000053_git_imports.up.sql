-- Git Capsule C1: importacion desde GitHub. El token de GitHub NUNCA se guarda: ninguna columna lo
-- contiene (vive solo en la memoria de la peticion en curso). request_hash cubre origen, repos e include.
CREATE TABLE IF NOT EXISTS git_imports (
    id              uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by      uuid         REFERENCES users(id) ON DELETE SET NULL,
    source          varchar(16)  NOT NULL DEFAULT 'github',
    status          varchar(10)  NOT NULL DEFAULT 'queued',
    include         text[]       NOT NULL DEFAULT '{}',
    create_projects boolean      NOT NULL DEFAULT true,
    idempotency_key varchar(128),
    request_hash    varchar(64)  NOT NULL DEFAULT '',
    attempts        integer      NOT NULL DEFAULT 1,
    created_at      timestamptz  NOT NULL DEFAULT now(),
    updated_at      timestamptz  NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    CONSTRAINT chk_git_imports_status CHECK (status IN ('queued', 'running', 'partial', 'success', 'failed')),
    CONSTRAINT chk_git_imports_source CHECK (source IN ('github'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_git_imports_idem ON git_imports(org_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_git_imports_org ON git_imports(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_git_imports_live ON git_imports(updated_at) WHERE status IN ('queued', 'running');

-- Estado por repositorio (reanudable: solo se repiten los que no estan en success).
CREATE TABLE IF NOT EXISTS git_import_repos (
    import_id       uuid         NOT NULL REFERENCES git_imports(id) ON DELETE CASCADE,
    name            varchar(201) NOT NULL,
    slug            varchar(100) NOT NULL,
    status          varchar(10)  NOT NULL DEFAULT 'queued',
    project_id      uuid         REFERENCES projects(id) ON DELETE SET NULL,
    created_project boolean      NOT NULL DEFAULT false,
    error           text         NOT NULL DEFAULT '',
    warnings        jsonb        NOT NULL DEFAULT '[]',
    codeowners      jsonb,
    attempts        integer      NOT NULL DEFAULT 0,
    started_at      timestamptz,
    finished_at     timestamptz,
    updated_at      timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (import_id, name),
    CONSTRAINT chk_git_import_repos_status CHECK (status IN ('queued', 'running', 'success', 'failed'))
);
CREATE INDEX IF NOT EXISTS idx_git_import_repos_slug ON git_import_repos(slug) WHERE status IN ('queued', 'running');
