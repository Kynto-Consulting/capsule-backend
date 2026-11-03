-- Removes UDP ports (their rules cascade; gateway services bound to a UDP port cascade too).
ALTER TABLE project_port_rules DROP CONSTRAINT IF EXISTS fk_project_port_rules_port_proto;
ALTER TABLE project_port_rules DROP CONSTRAINT IF EXISTS ck_project_port_rules_protocol;
DELETE FROM project_ports WHERE protocol <> 'tcp';
ALTER TABLE project_port_rules DROP COLUMN IF EXISTS protocol;
DROP INDEX IF EXISTS uq_project_ports_id_proto;
DROP INDEX IF EXISTS uq_project_ports_host_proto;
DROP INDEX IF EXISTS uq_project_ports_container_proto;
ALTER TABLE project_ports DROP CONSTRAINT IF EXISTS ck_project_ports_protocol;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_project_ports_container') THEN
        ALTER TABLE project_ports ADD CONSTRAINT uq_project_ports_container UNIQUE (project_id, container_port);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_project_ports_host') THEN
        ALTER TABLE project_ports ADD CONSTRAINT uq_project_ports_host UNIQUE (host_port);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'project_ports_protocol_check') THEN
        ALTER TABLE project_ports ADD CONSTRAINT project_ports_protocol_check CHECK (protocol = 'tcp');
    END IF;
END $$;
