CREATE TABLE IF NOT EXISTS org_env_vars (
    id         uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    key        varchar(255) NOT NULL,
    value_enc  bytea        NOT NULL,
    is_secret  boolean      NOT NULL DEFAULT true,
    scope      varchar(30)  NOT NULL DEFAULT 'runtime',
    created_at timestamptz  NOT NULL DEFAULT now(),
    updated_at timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_org_env_vars_org_key UNIQUE (org_id, key)
);
CREATE INDEX IF NOT EXISTS idx_org_env_vars_org ON org_env_vars(org_id);

-- Per-deployment env overrides (AES-GCM encrypted JSON object) + visible key names, and CI metadata.
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS env_enc  bytea;
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS env_keys text[];
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS meta     jsonb;

-- Project-scoped API tokens (scope "deploy").
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS project_id uuid REFERENCES projects(id) ON DELETE CASCADE;
