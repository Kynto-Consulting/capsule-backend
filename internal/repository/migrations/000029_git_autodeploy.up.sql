-- Git link per project (auto-deploy + PR previews).
CREATE TABLE IF NOT EXISTS project_git (
    project_id         uuid         PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    provider           varchar(20)  NOT NULL DEFAULT 'generic',
    repo_url           text         NOT NULL,
    branch             varchar(200) NOT NULL DEFAULT 'main',
    auth_kind          varchar(20)  NOT NULL DEFAULT 'none',
    auth_enc           bytea,
    webhook_secret_enc bytea,
    auto_deploy        boolean      NOT NULL DEFAULT false,
    preview_enabled    boolean      NOT NULL DEFAULT false,
    preview_max        int          NOT NULL DEFAULT 5,
    preview_ttl_hours  int          NOT NULL DEFAULT 168,
    created_at         timestamptz  NOT NULL DEFAULT now(),
    updated_at         timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_project_git_provider CHECK (provider IN ('github','forgejo','gitea','generic')),
    CONSTRAINT chk_project_git_auth CHECK (auth_kind IN ('token','ssh_key','none'))
);

-- Ephemeral preview projects (one per open pull request).
ALTER TABLE projects ADD COLUMN IF NOT EXISTS parent_project_id uuid REFERENCES projects(id) ON DELETE SET NULL;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS preview_pr int;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS preview_comment_id bigint;

CREATE INDEX IF NOT EXISTS idx_projects_parent ON projects(parent_project_id) WHERE parent_project_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_projects_expires ON projects(expires_at) WHERE expires_at IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_projects_preview_pr ON projects(parent_project_id, preview_pr)
    WHERE parent_project_id IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_deployments_project_trigger_status ON deployments(project_id, trigger, status);
