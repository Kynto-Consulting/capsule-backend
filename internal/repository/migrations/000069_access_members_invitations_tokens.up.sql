-- Miembros (columnas nuevas, role se conserva como etiqueta heredada), invitaciones, transferencias de propiedad y tokens con permisos.

ALTER TABLE org_members ADD COLUMN IF NOT EXISTS status           varchar(10) NOT NULL DEFAULT 'active';
ALTER TABLE org_members ADD COLUMN IF NOT EXISTS template_id      uuid REFERENCES role_templates(id);
-- NULL = sigue la ultima version de la plantilla (siempre asi con las del sistema); un entero la fija.
ALTER TABLE org_members ADD COLUMN IF NOT EXISTS template_version int;
ALTER TABLE org_members ADD COLUMN IF NOT EXISTS suspended_at     timestamptz;
ALTER TABLE org_members ADD COLUMN IF NOT EXISTS suspended_by     uuid REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE org_members ADD COLUMN IF NOT EXISTS invited_by       uuid REFERENCES users(id) ON DELETE SET NULL;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_org_members_status') THEN
        ALTER TABLE org_members ADD CONSTRAINT chk_org_members_status CHECK (status IN ('active', 'suspended'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_org_members_tver') THEN
        ALTER TABLE org_members ADD CONSTRAINT chk_org_members_tver CHECK (template_version IS NULL OR template_version >= 1);
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_org_members_template ON org_members(template_id) WHERE template_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS invitations (
    id          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email       varchar(255) NOT NULL,
    template_id uuid         NOT NULL REFERENCES role_templates(id),
    group_ids   uuid[]       NOT NULL DEFAULT '{}',
    assignments jsonb        NOT NULL DEFAULT '[]'::jsonb,
    token_hash  char(64)     NOT NULL,
    attempts    int          NOT NULL DEFAULT 0,
    invited_by  uuid         REFERENCES users(id) ON DELETE SET NULL,
    expires_at  timestamptz  NOT NULL,
    accepted_at timestamptz,
    accepted_by uuid         REFERENCES users(id) ON DELETE SET NULL,
    revoked_at  timestamptz,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_invitations_token UNIQUE (token_hash),
    CONSTRAINT chk_invitations_assign CHECK (jsonb_typeof(assignments) = 'array' AND jsonb_array_length(assignments) <= 20)
);
CREATE INDEX IF NOT EXISTS idx_invitations_org   ON invitations(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(lower(email));

CREATE TABLE IF NOT EXISTS ownership_transfers (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    from_user   uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_user     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    keep_owner  boolean     NOT NULL DEFAULT false,
    status      varchar(10) NOT NULL DEFAULT 'pending',
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    accepted_at timestamptz,
    CONSTRAINT chk_ownership_transfers_status CHECK (status IN ('pending', 'accepted', 'declined', 'cancelled', 'expired')),
    CONSTRAINT chk_ownership_transfers_users  CHECK (from_user <> to_user)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_ownership_transfers_pending ON ownership_transfers(org_id) WHERE status = 'pending';

-- NULL permissions => alcance heredado (SPEC 9.2), sin migracion de datos.
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS permissions text[];
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS org_id uuid REFERENCES organizations(id) ON DELETE CASCADE;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_api_tokens_permissions') THEN
        ALTER TABLE api_tokens ADD CONSTRAINT chk_api_tokens_permissions
            CHECK (permissions IS NULL OR (org_id IS NOT NULL AND access_perms_valid(permissions)));
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_api_tokens_org ON api_tokens(org_id) WHERE org_id IS NOT NULL;
