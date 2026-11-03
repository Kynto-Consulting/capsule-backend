-- Per-project roles (admin | deployer | viewer) layered over organization roles.
CREATE TABLE IF NOT EXISTS project_members (
    project_id uuid        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    role       varchar(20) NOT NULL,
    created_by uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, user_id),
    CONSTRAINT chk_project_members_role CHECK (role IN ('admin', 'deployer', 'viewer'))
);
CREATE INDEX IF NOT EXISTS idx_project_members_user ON project_members(user_id);

-- open: org members act as deployer on every project unless they have an explicit role.
-- restricted: org members only see projects where they have an explicit role.
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS project_access_mode varchar(12) NOT NULL DEFAULT 'open';
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_orgs_project_access_mode') THEN
        ALTER TABLE organizations ADD CONSTRAINT chk_orgs_project_access_mode
            CHECK (project_access_mode IN ('open', 'restricted'));
    END IF;
END $$;
