-- VPN Connector + funciones dentro del tunel (docs/vpn-connector.md). Migracion aditiva: no toca tablas existentes.
-- Un tunel por proyecto (UNIQUE project_id). Las credenciales van cifradas (AES-GCM con SECRET_KEY, igual que env_vars) y la API nunca las devuelve.
CREATE TABLE IF NOT EXISTS vpn_tunnels (
    id                uuid         PRIMARY KEY,
    org_id            uuid         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id        uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name              varchar(40)  NOT NULL,
    provider          varchar(16)  NOT NULL CHECK (provider IN ('wireguard','fortigate','ipsec','openvpn')),
    host              varchar(255) NOT NULL,
    cidrs             text[]       NOT NULL CHECK (cardinality(cidrs) > 0),
    cert_pin          varchar(64)  NOT NULL DEFAULT '',
    config            jsonb,
    secret_enc        bytea        NOT NULL,
    enabled           boolean      NOT NULL DEFAULT true,
    max_conns         int          NOT NULL DEFAULT 4 CHECK (max_conns BETWEEN 1 AND 64),
    bandwidth_bps     bigint       NOT NULL DEFAULT 8388608 CHECK (bandwidth_bps > 0),
    status            varchar(16)  NOT NULL DEFAULT 'down',
    last_handshake_at timestamptz,
    last_error        text         NOT NULL DEFAULT '',
    created_by        uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at        timestamptz  NOT NULL DEFAULT now(),
    updated_at        timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_vpn_tunnels_project UNIQUE (project_id)
);

CREATE TABLE IF NOT EXISTS vpn_events (
    id         bigserial   PRIMARY KEY,
    tunnel_id  uuid        NOT NULL,
    project_id uuid        NOT NULL,
    at         timestamptz NOT NULL DEFAULT now(),
    kind       varchar(24) NOT NULL,
    message    text        NOT NULL,
    actor      varchar(80) NOT NULL DEFAULT ''
);
-- Sin FK a vpn_tunnels: la auditoria sobrevive al borrado del tunel.
CREATE INDEX IF NOT EXISTS idx_vpn_events_tunnel ON vpn_events (tunnel_id, id DESC);

CREATE TABLE IF NOT EXISTS fn_functions (
    id              uuid         PRIMARY KEY,
    org_id          uuid         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id      uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name            varchar(40)  NOT NULL,
    image           varchar(255) NOT NULL,
    entry           varchar(255) NOT NULL DEFAULT '',
    vpn_id          uuid         REFERENCES vpn_tunnels(id) ON DELETE SET NULL,
    cron            varchar(64)  NOT NULL DEFAULT '',
    memory_mb       int          NOT NULL CHECK (memory_mb BETWEEN 64 AND 4096),
    cpus            real         NOT NULL CHECK (cpus BETWEEN 0.1 AND 4),
    timeout_seconds int          NOT NULL CHECK (timeout_seconds BETWEEN 10 AND 21600),
    max_concurrency int          NOT NULL DEFAULT 1 CHECK (max_concurrency BETWEEN 1 AND 8),
    scopes          text[]       NOT NULL DEFAULT '{}',
    enabled         boolean      NOT NULL DEFAULT true,
    last_cron_at    timestamptz,
    created_by      uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_fn_functions_name UNIQUE (project_id, name)
);

CREATE TABLE IF NOT EXISTS fn_runs (
    id           uuid         PRIMARY KEY,
    function_id  uuid         NOT NULL REFERENCES fn_functions(id) ON DELETE CASCADE,
    project_id   uuid         NOT NULL,
    trigger      varchar(8)   NOT NULL CHECK (trigger IN ('cron','api','queue')),
    triggered_by varchar(80)  NOT NULL DEFAULT '',
    status       varchar(10)  NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','succeeded','failed','cancelled','timeout')),
    queued_at    timestamptz  NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz,
    exit_code    int,
    scopes       text[]       NOT NULL DEFAULT '{}',
    bytes_in     bigint       NOT NULL DEFAULT 0,
    bytes_out    bigint       NOT NULL DEFAULT 0,
    node_id      varchar(80)  NOT NULL DEFAULT '',
    payload      jsonb,
    log_tail     text         NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_fn_runs_function ON fn_runs (function_id, queued_at DESC);
CREATE INDEX IF NOT EXISTS idx_fn_runs_status ON fn_runs (status, queued_at) WHERE status IN ('queued','running');

-- Token de corta vida de una corrida (capfn_). Solo se guarda el SHA-256.
CREATE TABLE IF NOT EXISTS fn_run_tokens (
    token_hash varchar(64) PRIMARY KEY,
    run_id     uuid        NOT NULL REFERENCES fn_runs(id) ON DELETE CASCADE,
    project_id uuid        NOT NULL,
    scopes     text[]      NOT NULL DEFAULT '{}',
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_fn_run_tokens_run ON fn_run_tokens (run_id);

-- Nodos de trabajo (capnode_): solo hacen conexiones salientes hacia la API.
CREATE TABLE IF NOT EXISTS fn_nodes (
    id           uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    name         varchar(80)  NOT NULL UNIQUE,
    token_hash   varchar(64)  NOT NULL UNIQUE,
    last_seen_at timestamptz,
    created_at   timestamptz  NOT NULL DEFAULT now()
);
