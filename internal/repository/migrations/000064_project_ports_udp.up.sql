-- UDP direct ports (no tunnel): project ports and their access rules carry a protocol.
-- The public port still comes from the same range; uniqueness is per (port, protocol).
-- Existing rows keep protocol 'tcp' (the column already existed with CHECK = 'tcp').

ALTER TABLE project_ports DROP CONSTRAINT IF EXISTS project_ports_protocol_check;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_project_ports_protocol') THEN
        ALTER TABLE project_ports ADD CONSTRAINT ck_project_ports_protocol CHECK (protocol IN ('tcp','udp'));
    END IF;
END $$;

-- Same number may exist as tcp and udp, in the container and on the host.
ALTER TABLE project_ports DROP CONSTRAINT IF EXISTS uq_project_ports_container;
ALTER TABLE project_ports DROP CONSTRAINT IF EXISTS uq_project_ports_host;
CREATE UNIQUE INDEX IF NOT EXISTS uq_project_ports_container_proto ON project_ports (project_id, container_port, protocol);
CREATE UNIQUE INDEX IF NOT EXISTS uq_project_ports_host_proto ON project_ports (host_port, protocol);
CREATE UNIQUE INDEX IF NOT EXISTS uq_project_ports_id_proto ON project_ports (id, protocol);

-- Rules repeat the protocol of their port; the composite FK keeps them equal.
ALTER TABLE project_port_rules ADD COLUMN IF NOT EXISTS protocol varchar(8) NOT NULL DEFAULT 'tcp';
UPDATE project_port_rules r SET protocol = p.protocol FROM project_ports p WHERE p.id = r.port_id AND r.protocol <> p.protocol;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_project_port_rules_protocol') THEN
        ALTER TABLE project_port_rules ADD CONSTRAINT ck_project_port_rules_protocol CHECK (protocol IN ('tcp','udp'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_project_port_rules_port_proto') THEN
        ALTER TABLE project_port_rules ADD CONSTRAINT fk_project_port_rules_port_proto
            FOREIGN KEY (port_id, protocol) REFERENCES project_ports (id, protocol) ON DELETE CASCADE;
    END IF;
END $$;
