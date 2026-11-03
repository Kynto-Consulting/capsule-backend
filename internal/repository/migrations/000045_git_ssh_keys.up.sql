-- Git Capsule A7: public SSH keys managed from Capsule and synchronized with Forgejo (acting as the user).
CREATE TABLE IF NOT EXISTS git_ssh_keys (
    id              uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title           varchar(100) NOT NULL,
    public_key      text         NOT NULL,
    key_type        varchar(32)  NOT NULL,
    fingerprint     varchar(80)  NOT NULL,
    forgejo_key_id  bigint,
    synced_at       timestamptz,
    sync_error      text         NOT NULL DEFAULT '',
    sync_attempts   integer      NOT NULL DEFAULT 0,
    next_sync_at    timestamptz  NOT NULL DEFAULT now(),
    last_used_at    timestamptz,
    deleted_at      timestamptz,
    created_at      timestamptz  NOT NULL DEFAULT now()
);
-- One live registration per key across Capsule (Forgejo also refuses duplicates).
CREATE UNIQUE INDEX IF NOT EXISTS uq_git_ssh_keys_fingerprint ON git_ssh_keys(fingerprint) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_git_ssh_keys_user ON git_ssh_keys(user_id, created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_git_ssh_keys_pending ON git_ssh_keys(next_sync_at) WHERE (synced_at IS NULL AND deleted_at IS NULL) OR (deleted_at IS NOT NULL AND forgejo_key_id IS NOT NULL);
