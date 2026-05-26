BEGIN;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id                uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    email             varchar(255) NOT NULL,
    password_hash     varchar(255) NOT NULL,
    name              varchar(100) NOT NULL,
    avatar_url        text,
    role              varchar(20)  NOT NULL DEFAULT 'member',
    email_verified_at timestamptz,
    last_login_at     timestamptz,
    created_at        timestamptz  NOT NULL DEFAULT now(),
    updated_at        timestamptz  NOT NULL DEFAULT now(),
    deleted_at        timestamptz,

    CONSTRAINT uq_users_email UNIQUE (email)
);

CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_role  ON users(role)  WHERE deleted_at IS NULL;

COMMIT;
