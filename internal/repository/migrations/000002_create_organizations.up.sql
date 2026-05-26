BEGIN;

CREATE TABLE organizations (
    id         uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    name       varchar(100) NOT NULL,
    slug       varchar(100) NOT NULL,
    owner_id   uuid         NOT NULL REFERENCES users(id),
    plan       varchar(30)  NOT NULL DEFAULT 'free',
    settings   jsonb        NOT NULL DEFAULT '{}',
    created_at timestamptz  NOT NULL DEFAULT now(),
    updated_at timestamptz  NOT NULL DEFAULT now(),
    deleted_at timestamptz,

    CONSTRAINT uq_orgs_slug UNIQUE (slug)
);

CREATE TABLE org_members (
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       varchar(20) NOT NULL DEFAULT 'member',
    joined_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (org_id, user_id)
);

CREATE INDEX idx_orgs_owner ON organizations(owner_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_orgs_slug  ON organizations(slug)     WHERE deleted_at IS NULL;
CREATE INDEX idx_org_members_user ON org_members(user_id);

COMMIT;
