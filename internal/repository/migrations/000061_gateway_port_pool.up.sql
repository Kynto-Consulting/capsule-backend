-- Random-port fallback: pool of public ports, leases, quarantine and per-organisation quotas (PLAN 3.4).
CREATE TABLE IF NOT EXISTS gateway_port_pool (
    port              integer      PRIMARY KEY CHECK (port BETWEEN 1024 AND 65535),
    state             varchar(10)  NOT NULL DEFAULT 'free',
    last_org_id       uuid,
    quarantine_until  timestamptz,
    CONSTRAINT ck_gateway_port_pool_state CHECK (state IN ('free','leased','quarantine'))
);
CREATE INDEX IF NOT EXISTS idx_gateway_port_pool_state ON gateway_port_pool (state);

CREATE TABLE IF NOT EXISTS gateway_port_leases (
    id            uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    port          integer      NOT NULL REFERENCES gateway_port_pool(port),
    service_id    uuid         NOT NULL REFERENCES gateway_services(id) ON DELETE CASCADE,
    project_id    uuid,
    org_id        uuid         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    state         varchar(10)  NOT NULL DEFAULT 'active',
    leased_at     timestamptz  NOT NULL DEFAULT now(),
    released_at   timestamptz,
    last_conn_at  timestamptz,
    CONSTRAINT ck_gateway_port_leases_state CHECK (state IN ('active','released'))
);
-- One active lease per port and per service.
CREATE UNIQUE INDEX IF NOT EXISTS uq_gateway_port_leases_active_port ON gateway_port_leases (port) WHERE state = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS uq_gateway_port_leases_active_service ON gateway_port_leases (service_id) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS idx_gateway_port_leases_org ON gateway_port_leases (org_id) WHERE state = 'active';

-- Per-organisation quotas; no row = defaults (20 per org, 5 per project).
CREATE TABLE IF NOT EXISTS gateway_org_quotas (
    org_id                 uuid        PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    max_random_ports       integer     NOT NULL DEFAULT 20 CHECK (max_random_ports >= 0),
    max_random_ports_proj  integer     NOT NULL DEFAULT 5 CHECK (max_random_ports_proj >= 0),
    updated_at             timestamptz NOT NULL DEFAULT now()
);
