-- Universal gateway, data model (docs/gateway/PLAN.md 5.1).
-- A "service" is a named port of a project; its NAME is the service name (unique per scope, DNS label).
-- Each service has up to two accesses: 'gateway' (primary) and 'direct_port' (secondary, today's published port).

CREATE TABLE IF NOT EXISTS gateway_services (
    id              uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id      uuid         REFERENCES projects(id) ON DELETE CASCADE,
    name            varchar(63)  NOT NULL,
    protocol        varchar(10)  NOT NULL DEFAULT 'tcp',
    container_port  integer      NOT NULL DEFAULT 0 CHECK (container_port BETWEEN 0 AND 65535),
    default_access  varchar(12)  NOT NULL DEFAULT 'gateway',
    project_port_id uuid         REFERENCES project_ports(id) ON DELETE CASCADE,
    database_id     uuid         REFERENCES databases(id) ON DELETE CASCADE,
    created_at      timestamptz  NOT NULL DEFAULT now(),
    updated_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT ck_gateway_services_name CHECK (name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'),
    CONSTRAINT ck_gateway_services_protocol CHECK (protocol IN ('http','tls','postgres','mysql','redis','mongo','ssh','tcp','udp')),
    CONSTRAINT ck_gateway_services_default_access CHECK (default_access IN ('gateway','direct_port')),
    CONSTRAINT ck_gateway_services_one_source CHECK (project_port_id IS NULL OR database_id IS NULL)
);
-- Name is unique per project; org-level services (project_id NULL) are unique per org.
CREATE UNIQUE INDEX IF NOT EXISTS uq_gateway_services_scope_name
    ON gateway_services (org_id, COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid), name);
CREATE UNIQUE INDEX IF NOT EXISTS uq_gateway_services_project_port ON gateway_services (project_port_id) WHERE project_port_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_gateway_services_database ON gateway_services (database_id) WHERE database_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_gateway_services_project ON gateway_services (project_id);

-- Two accesses per service. direct_port points at the existing published port (not duplicated).
CREATE TABLE IF NOT EXISTS gateway_accesses (
    id          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id  uuid         NOT NULL REFERENCES gateway_services(id) ON DELETE CASCADE,
    kind        varchar(12)  NOT NULL,
    enabled     boolean      NOT NULL DEFAULT true,
    port        integer      CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    created_at  timestamptz  NOT NULL DEFAULT now(),
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT ck_gateway_accesses_kind CHECK (kind IN ('gateway','direct_port')),
    CONSTRAINT uq_gateway_accesses_service_kind UNIQUE (service_id, kind)
);

-- Single-row revision counter: bumped in the same transaction as any route change (long-poll snapshot).
CREATE TABLE IF NOT EXISTS gateway_revision (
    id   boolean PRIMARY KEY DEFAULT true CHECK (id),
    rev  bigint  NOT NULL DEFAULT 0
);
INSERT INTO gateway_revision (id, rev) VALUES (true, 0) ON CONFLICT (id) DO NOTHING;

-- Route table read by the data plane: host/SNI -> internal destination.
CREATE TABLE IF NOT EXISTS gateway_routes (
    id          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id  uuid         NOT NULL REFERENCES gateway_services(id) ON DELETE CASCADE,
    host        varchar(253) NOT NULL,
    transport   varchar(3)   NOT NULL DEFAULT 'tcp',
    protocol    varchar(10)  NOT NULL DEFAULT 'tcp',
    dest_host   varchar(255) NOT NULL,
    dest_port   integer      NOT NULL CHECK (dest_port BETWEEN 1 AND 65535),
    mode        varchar(11)  NOT NULL DEFAULT 'passthrough',
    enabled     boolean      NOT NULL DEFAULT true,
    rev         bigint       NOT NULL DEFAULT 0,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT ck_gateway_routes_transport CHECK (transport IN ('tcp','udp')),
    CONSTRAINT ck_gateway_routes_protocol CHECK (protocol IN ('http','tls','postgres','mysql','redis','mongo','ssh','tcp','udp')),
    CONSTRAINT ck_gateway_routes_mode CHECK (mode IN ('passthrough','terminate')),
    CONSTRAINT ck_gateway_routes_host CHECK (host = lower(host) AND host <> ''),
    CONSTRAINT uq_gateway_routes_host UNIQUE (transport, host)
);
CREATE INDEX IF NOT EXISTS idx_gateway_routes_service ON gateway_routes (service_id);
