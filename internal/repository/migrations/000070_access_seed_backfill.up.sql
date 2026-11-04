-- Siembra de las plantillas del sistema y backfill de miembros y asignaciones (MIGRATION sec. 2). Idempotente.
--
-- Esta migracion fija la IDENTIDAD de las plantillas (UUID v5 deterministas, igual que repository.SystemTemplateID) y deja
-- current_version = 1. El CONTENIDO de la version 1 (permisos, floor, base, ceiling) sale de authz/systemtemplates.json y lo
-- inserta repository.SeedSystemTemplates (INSERT ... ON CONFLICT DO NOTHING) porque SQL no puede leer ese archivo.

-- UUID v5 (RFC 4122, SHA-1) en SQL; coincide byte a byte con github.com/google/uuid NewSHA1.
CREATE OR REPLACE FUNCTION access_uuid_v5(ns uuid, nm text) RETURNS uuid AS $$
DECLARE
    h bytea;
BEGIN
    h := digest(decode(replace(ns::text, '-', ''), 'hex') || convert_to(nm, 'UTF8'), 'sha1');
    h := set_byte(h, 6, (get_byte(h, 6) & 15) | 80);
    h := set_byte(h, 8, (get_byte(h, 8) & 63) | 128);
    RETURN encode(substring(h from 1 for 16), 'hex')::uuid;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Namespace de las plantillas del sistema: uuid v5(URL, 'urn:capsule:permissions:system-templates'), igual que systemtemplates.Namespace.
CREATE OR REPLACE FUNCTION access_system_template_id(k text, s text) RETURNS uuid AS $$
    SELECT access_uuid_v5('04f66add-c6a6-5714-aa88-8166877f93a9'::uuid, k || '/' || s);
$$ LANGUAGE sql IMMUTABLE;

INSERT INTO role_templates (id, org_id, kind, slug, name, description, system, current_version)
SELECT access_system_template_id(v.kind, v.slug), NULL, v.kind, v.slug, v.name, v.descr, true, 1
  FROM (VALUES
    ('org', 'owner', 'Owner', 'Propietario de la organización: todo, con acceso de administrador a todos los proyectos'),
    ('org', 'admin', 'Admin', 'Administrador de la organización: acceso de administrador a todos los proyectos'),
    ('org', 'member', 'Member', 'Miembro: despliega en los proyectos abiertos y ve solo los suyos en organizaciones restringidas'),
    ('org', 'readonly', 'Readonly', 'Solo lectura: nunca más que viewer, aunque una asignación diga otra cosa'),
    ('project', 'viewer', 'Viewer', 'Ve el proyecto, el código, las alertas y los entornos'),
    ('project', 'deployer', 'Deployer', 'Despliega, edita variables y operaciones del proyecto y trabaja con el código'),
    ('project', 'admin', 'Admin', 'Administra el proyecto (todo salvo aprobar promociones, que decide cada entorno)'),
    ('repo', 'repo-read', 'Repo read', 'Lee el código y la CI de un repositorio'),
    ('repo', 'repo-write', 'Repo write', 'Lee y escribe código, revisa, fusiona y lanza CI en un repositorio')
  ) AS v(kind, slug, name, descr)
ON CONFLICT DO NOTHING;

-- org_members.role -> plantilla de organizacion del sistema con ese slug. Rol desconocido: template_id NULL (el motor lo trata como no resuelve).
UPDATE org_members om SET template_id = t.id
  FROM role_templates t
 WHERE t.system AND t.kind = 'org' AND t.slug = om.role AND om.template_id IS NULL;

INSERT INTO access_anomalies (kind, org_id, user_id, detail)
SELECT 'org_members.role.unknown', om.org_id, om.user_id, om.role FROM org_members om
 WHERE om.template_id IS NULL
   AND NOT EXISTS (SELECT 1 FROM access_anomalies a WHERE a.kind = 'org_members.role.unknown' AND a.org_id = om.org_id AND a.user_id = om.user_id);

-- project_members -> una asignacion por fila (usuario, alcance proyecto, plantilla de proyecto del sistema = role).
INSERT INTO access_assignments (org_id, subject_type, subject_id, scope_type, scope_id, template_id, source, created_by, created_at)
SELECT p.org_id, 'user', pm.user_id, 'project', pm.project_id, t.id, 'migrated', pm.created_by, pm.created_at
  FROM project_members pm
  JOIN projects p ON p.id = pm.project_id
  JOIN role_templates t ON t.system AND t.kind = 'project' AND t.slug = pm.role
ON CONFLICT (subject_type, subject_id, scope_type, scope_id, template_id) WHERE revoked_at IS NULL DO NOTHING;
