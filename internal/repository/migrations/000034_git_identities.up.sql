-- Git Capsule A2: identidad usuario Capsule <-> usuario Forgejo.
-- El login de Forgejo es el preferred_username del OIDC. forgejo_user_id y linked_at quedan NULL
-- hasta que se confirma que el usuario existe en Forgejo (primer login real o reconciliacion).
CREATE TABLE IF NOT EXISTS git_identities (
    user_id          uuid         PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    forgejo_username varchar(64)  NOT NULL,
    forgejo_user_id  bigint,
    linked_at        timestamptz,
    created_at       timestamptz  NOT NULL DEFAULT now(),
    updated_at       timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_git_identities_username CHECK (forgejo_username <> '')
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_git_identities_username ON git_identities (lower(forgejo_username));
CREATE UNIQUE INDEX IF NOT EXISTS uq_git_identities_forgejo_id ON git_identities (forgejo_user_id) WHERE forgejo_user_id IS NOT NULL;
