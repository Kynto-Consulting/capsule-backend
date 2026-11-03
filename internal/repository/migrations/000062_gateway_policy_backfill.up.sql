-- Organisation policy for connections that bypass the gateway (PLAN 11.5): warn (default) | error.
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS gateway_policy varchar(5) NOT NULL DEFAULT 'warn';
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_organizations_gateway_policy') THEN
        ALTER TABLE organizations ADD CONSTRAINT ck_organizations_gateway_policy CHECK (gateway_policy IN ('warn','error'));
    END IF;
END $$;

-- Existing project ports keep working exactly as today: default_access = direct_port, gateway access off.
INSERT INTO gateway_services (org_id, project_id, name, protocol, container_port, default_access, project_port_id)
SELECT c.org_id, c.project_id, c.name, 'tcp', c.container_port, 'direct_port', c.id
FROM (
    SELECT p.id, p.project_id, p.container_port, pr.org_id,
           CASE WHEN row_number() OVER (PARTITION BY p.project_id, b.base ORDER BY p.container_port) > 1
                THEN left(b.base, 56) || '-' || p.container_port ELSE b.base END AS name
    FROM project_ports p
    JOIN projects pr ON pr.id = p.project_id
    CROSS JOIN LATERAL (
        SELECT COALESCE(NULLIF(left(trim(both '-' from regexp_replace(lower(p.name), '[^a-z0-9]+', '-', 'g')), 50), ''),
                        'port-' || p.container_port) AS base
    ) b
) c
WHERE NOT EXISTS (SELECT 1 FROM gateway_services s WHERE s.project_port_id = c.id)
ON CONFLICT DO NOTHING;

INSERT INTO gateway_accesses (service_id, kind, enabled, port)
SELECT s.id, 'direct_port', true, p.host_port
FROM gateway_services s JOIN project_ports p ON p.id = s.project_port_id
ON CONFLICT (service_id, kind) DO NOTHING;

INSERT INTO gateway_accesses (service_id, kind, enabled, port)
SELECT s.id, 'gateway', false, NULL
FROM gateway_services s
WHERE s.project_port_id IS NOT NULL OR s.database_id IS NOT NULL
ON CONFLICT (service_id, kind) DO NOTHING;

-- Existing databases: same treatment.
INSERT INTO gateway_services (org_id, project_id, name, protocol, container_port, default_access, database_id)
SELECT c.org_id, c.project_id, c.name, c.protocol, c.port, 'direct_port', c.id
FROM (
    SELECT d.id, d.org_id, d.project_id, d.port,
           CASE WHEN d.engine ILIKE 'postgres%' THEN 'postgres'
                WHEN d.engine ILIKE 'mysql%' OR d.engine ILIKE 'maria%' THEN 'mysql'
                ELSE 'tcp' END AS protocol,
           CASE WHEN row_number() OVER (PARTITION BY d.org_id, d.project_id, b.base ORDER BY d.created_at, d.id) > 1
                THEN left(b.base, 50) || '-' || left(d.id::text, 8) ELSE b.base END AS name
    FROM databases d
    CROSS JOIN LATERAL (
        SELECT COALESCE(NULLIF(left(trim(both '-' from regexp_replace(lower(d.name), '[^a-z0-9]+', '-', 'g')), 50), ''),
                        'db-' || left(d.id::text, 8)) AS base
    ) b
    WHERE d.deleted_at IS NULL
) c
WHERE NOT EXISTS (SELECT 1 FROM gateway_services s WHERE s.database_id = c.id)
ON CONFLICT DO NOTHING;

INSERT INTO gateway_accesses (service_id, kind, enabled, port)
SELECT s.id, 'direct_port', true, d.port
FROM gateway_services s JOIN databases d ON d.id = s.database_id
ON CONFLICT (service_id, kind) DO NOTHING;

INSERT INTO gateway_accesses (service_id, kind, enabled, port)
SELECT s.id, 'gateway', false, NULL
FROM gateway_services s
WHERE s.database_id IS NOT NULL
ON CONFLICT (service_id, kind) DO NOTHING;
