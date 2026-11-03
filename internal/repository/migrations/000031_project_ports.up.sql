-- Extra TCP ports published by a project's container on the app host.
CREATE TABLE IF NOT EXISTS project_ports (
    id             uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id     uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name           varchar(40)  NOT NULL DEFAULT '',
    container_port integer      NOT NULL CHECK (container_port BETWEEN 1 AND 65535),
    protocol       varchar(8)   NOT NULL DEFAULT 'tcp' CHECK (protocol = 'tcp'),
    host_port      integer      NOT NULL CHECK (host_port BETWEEN 1024 AND 65535),
    created_at     timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_project_ports_container UNIQUE (project_id, container_port),
    CONSTRAINT uq_project_ports_host UNIQUE (host_port)
);
CREATE INDEX IF NOT EXISTS idx_project_ports_project ON project_ports(project_id);

-- Who may reach each published port from the internet (applied to the host security group).
CREATE TABLE IF NOT EXISTS project_port_rules (
    id          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    port_id     uuid         NOT NULL REFERENCES project_ports(id) ON DELETE CASCADE,
    cidr        varchar(18)  NOT NULL,
    description text         NOT NULL DEFAULT '',
    created_by  uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_project_port_rules_port_cidr UNIQUE (port_id, cidr)
);
CREATE INDEX IF NOT EXISTS idx_project_port_rules_port ON project_port_rules(port_id);
