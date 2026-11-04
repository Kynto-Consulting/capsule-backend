-- Deshace el backfill. Las tablas viejas (org_members.role, project_members, users.role) no se tocan. Las filas de identidad de las
-- plantillas del sistema se quedan (son inertes y un up posterior las reconoce); las borra el down de 000067 junto con la tabla.
-- Idempotente: si las tablas nuevas ya no existen no hace nada.
DO $$
BEGIN
    IF to_regclass('access_assignments') IS NOT NULL THEN
        DELETE FROM access_assignments WHERE source IN ('migrated', 'legacy-api');
    END IF;
    IF to_regclass('role_templates') IS NOT NULL AND EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'org_members' AND column_name = 'template_id') THEN
        UPDATE org_members SET template_id = NULL, template_version = NULL WHERE template_id IN (SELECT id FROM role_templates WHERE system);
    END IF;
    IF to_regclass('access_anomalies') IS NOT NULL THEN
        DELETE FROM access_anomalies WHERE kind = 'org_members.role.unknown';
    END IF;
END $$;
DROP FUNCTION IF EXISTS access_system_template_id(text, text);
DROP FUNCTION IF EXISTS access_uuid_v5(uuid, text);
