-- OpenID Connect provider: registered clients, pending authorization requests,
-- authorization codes and refresh tokens. Secrets, codes and refresh tokens are
-- stored only as SHA-256 hashes.
CREATE TABLE IF NOT EXISTS oauth_clients (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id     text        NOT NULL UNIQUE,
    secret_hash   text        NOT NULL DEFAULT '',      -- empty = public client (PKCE only)
    name          text        NOT NULL,
    redirect_uris text[]      NOT NULL DEFAULT '{}',
    org_id        uuid        REFERENCES organizations(id) ON DELETE CASCADE,
    first_party   boolean     NOT NULL DEFAULT false,
    created_by    uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz
);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_org ON oauth_clients(org_id);

CREATE TABLE IF NOT EXISTS oauth_requests (
    id             text        PRIMARY KEY,             -- random, unguessable
    client_id      uuid        NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    redirect_uri   text        NOT NULL,
    scope          text        NOT NULL DEFAULT '',
    state          text        NOT NULL DEFAULT '',
    nonce          text        NOT NULL DEFAULT '',
    code_challenge text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_requests_expires ON oauth_requests(expires_at);

CREATE TABLE IF NOT EXISTS oauth_codes (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(), -- also the grant id
    code_hash      text        NOT NULL UNIQUE,
    client_id      uuid        NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id        uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri   text        NOT NULL,
    scope          text        NOT NULL DEFAULT '',
    nonce          text        NOT NULL DEFAULT '',
    code_challenge text        NOT NULL DEFAULT '',
    auth_time      timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    revoked_at     timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_client ON oauth_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_user ON oauth_codes(user_id);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash  text        NOT NULL UNIQUE,
    grant_id    uuid        NOT NULL REFERENCES oauth_codes(id) ON DELETE CASCADE,
    client_id   uuid        NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope       text        NOT NULL DEFAULT '',
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    revoked_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_grant ON oauth_refresh_tokens(grant_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_client ON oauth_refresh_tokens(client_id);
