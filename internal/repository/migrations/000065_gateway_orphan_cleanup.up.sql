-- Gateway: services, routes, accesses and leases die with the project, database or published port they mirror.
-- Projects and databases are SOFT-deleted (deleted_at), so the ON DELETE CASCADE foreign keys of 000060 never fire for the
-- normal delete path: these triggers treat deleted_at as a delete. A released random port goes to a 24 h quarantine
-- (same as DeleteService) and the route revision is bumped so the data plane drops the route on its next poll.

CREATE OR REPLACE FUNCTION gateway_purge_services(p_project uuid, p_database uuid, p_port uuid) RETURNS integer AS $$
DECLARE
    ids uuid[];
    n   integer;
BEGIN
    PERFORM pg_advisory_xact_lock(('x4341504750504f4c')::bit(64)::bigint); -- same lock as the store's pool mutations
    SELECT coalesce(array_agg(id), '{}') INTO ids FROM gateway_services
     WHERE (p_project  IS NOT NULL AND project_id = p_project)
        OR (p_database IS NOT NULL AND database_id = p_database)
        OR (p_port     IS NOT NULL AND project_port_id = p_port);
    IF coalesce(array_length(ids, 1), 0) = 0 THEN
        RETURN 0;
    END IF;
    UPDATE gateway_port_pool SET state = 'quarantine', quarantine_until = now() + interval '24 hours'
     WHERE port IN (SELECT port FROM gateway_port_leases WHERE service_id = ANY(ids) AND state = 'active');
    UPDATE gateway_port_leases SET state = 'released', released_at = now() WHERE service_id = ANY(ids) AND state = 'active';
    DELETE FROM gateway_services WHERE id = ANY(ids);
    GET DIAGNOSTICS n = ROW_COUNT;
    UPDATE gateway_revision SET rev = rev + 1 WHERE id;
    RETURN n;
END;
$$ LANGUAGE plpgsql;

-- Services whose source no longer exists (deleted or soft-deleted project/database, removed published port). Used by the
-- periodic sweep as a safety net; returns how many services were removed.
CREATE OR REPLACE FUNCTION gateway_purge_orphans() RETURNS integer AS $$
DECLARE
    r record;
    total integer := 0;
BEGIN
    FOR r IN
        SELECT DISTINCT s.project_id, s.database_id, s.project_port_id FROM gateway_services s
         WHERE (s.project_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM projects p WHERE p.id = s.project_id AND p.deleted_at IS NULL))
            OR (s.database_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM databases d WHERE d.id = s.database_id AND d.deleted_at IS NULL))
            OR (s.project_port_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM project_ports pp WHERE pp.id = s.project_port_id))
    LOOP
        IF r.database_id IS NOT NULL THEN
            total := total + gateway_purge_services(NULL, r.database_id, NULL);
        ELSIF r.project_port_id IS NOT NULL THEN
            total := total + gateway_purge_services(NULL, NULL, r.project_port_id);
        ELSE
            total := total + gateway_purge_services(r.project_id, NULL, NULL);
        END IF;
    END LOOP;
    RETURN total;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION gateway_trg_project() RETURNS trigger AS $$
BEGIN
    PERFORM gateway_purge_services(OLD.id, NULL, NULL);
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION gateway_trg_database() RETURNS trigger AS $$
BEGIN
    PERFORM gateway_purge_services(NULL, OLD.id, NULL);
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION gateway_trg_project_port() RETURNS trigger AS $$
BEGIN
    PERFORM gateway_purge_services(NULL, NULL, OLD.id);
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS gateway_project_soft_delete ON projects;
CREATE TRIGGER gateway_project_soft_delete AFTER UPDATE OF deleted_at ON projects
    FOR EACH ROW WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL) EXECUTE FUNCTION gateway_trg_project();
DROP TRIGGER IF EXISTS gateway_project_delete ON projects;
CREATE TRIGGER gateway_project_delete BEFORE DELETE ON projects FOR EACH ROW EXECUTE FUNCTION gateway_trg_project();

DROP TRIGGER IF EXISTS gateway_database_soft_delete ON databases;
CREATE TRIGGER gateway_database_soft_delete AFTER UPDATE OF deleted_at ON databases
    FOR EACH ROW WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL) EXECUTE FUNCTION gateway_trg_database();
DROP TRIGGER IF EXISTS gateway_database_delete ON databases;
CREATE TRIGGER gateway_database_delete BEFORE DELETE ON databases FOR EACH ROW EXECUTE FUNCTION gateway_trg_database();

DROP TRIGGER IF EXISTS gateway_project_port_delete ON project_ports;
CREATE TRIGGER gateway_project_port_delete BEFORE DELETE ON project_ports FOR EACH ROW EXECUTE FUNCTION gateway_trg_project_port();

-- One-off cleanup of what earlier deletes left behind.
SELECT gateway_purge_orphans();
