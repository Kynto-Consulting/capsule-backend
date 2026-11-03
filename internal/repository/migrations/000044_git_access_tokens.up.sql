-- Git Capsule A7: tokens cgt_ for Git over HTTPS (validated at the edge through /internal/git-auth).
-- Only the SHA-256 of the token is stored, never the value.
CREATE TABLE IF NOT EXISTS git_access_tokens (
    id             uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind           varchar(16)  NOT NULL CHECK (kind IN ('ephemeral', 'personal', 'service')),
    name           varchar(100) NOT NULL DEFAULT '',
    token_hash     char(64)     NOT NULL,
    prefix         varchar(12)  NOT NULL,
    scope          varchar(8)   NOT NULL CHECK (scope IN ('read', 'write')),
    project_ids    uuid[]       NOT NULL DEFAULT '{}',
    session_ref    varchar(80),
    created_ip     inet,
    expires_at     timestamptz  NOT NULL,
    last_used_at   timestamptz,
    last_used_ip   inet,
    revoked_at     timestamptz,
    revoked_reason varchar(40),
    expiry_warned_at timestamptz,
    created_at     timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_git_access_tokens_hash UNIQUE (token_hash)
);
CREATE INDEX IF NOT EXISTS idx_git_access_tokens_user ON git_access_tokens(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_git_access_tokens_session ON git_access_tokens(user_id, session_ref) WHERE revoked_at IS NULL AND session_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_git_access_tokens_expiry ON git_access_tokens(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_git_access_tokens_projects ON git_access_tokens USING gin (project_ids);
