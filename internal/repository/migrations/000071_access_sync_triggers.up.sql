-- Triggers de sincronizacion entre el esquema viejo y el nuevo (MIGRATION F1). Mientras el codigo viejo escriba project_members,
-- org_members.role y users.role, las tablas nuevas se mantienen solas, y al reves.
--
-- Anti-bucle: toda escritura que un trigger hace en la tabla "espejo" va con la bandera transaccional capsule.access_sync = 'on';
-- los triggers de sincronizacion que la ven encendida no hacen nada. Los triggers BEFORE solo modifican NEW (no escriben en otra tabla de
-- sincronizacion). Se usa una bandera y no pg_trigger_depth() porque las cascadas de claves foraneas (borrar un proyecto o un usuario)
-- anidan los triggers un nivel mas y una guarda por profundidad se saltaria justo esas bajas.
--
-- Cada escritura por el camino viejo incrementa organizations.access_epoch y hace NOTIFY capsule_access en la misma transaccion, para
-- que la comparacion en sombra (F2) vea el cambio.

-- Epoch por organizacion + NOTIFY (una sola implementacion, la usan los triggers y los comandos de repository.AccessStore).
CREATE OR REPLACE FUNCTION access_bump_org(p_org uuid) RETURNS bigint AS $$
DECLARE
    e bigint;
BEGIN
    UPDATE organizations SET access_epoch = access_epoch + 1 WHERE id = p_org RETURNING access_epoch INTO e;
    IF e IS NOT NULL THEN
        PERFORM pg_notify('capsule_access', p_org::text);
    END IF;
    RETURN e;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION access_sync_busy() RETURNS boolean AS $$
    SELECT coalesce(current_setting('capsule.access_sync', true), '') = 'on';
$$ LANGUAGE sql STABLE;

-- ---------------------------------------------------------------- users.role <-> platform_role/status
CREATE OR REPLACE FUNCTION access_trg_users_sync() RETURNS trigger AS $$
DECLARE
    role_ch boolean;
    plat_ch boolean;
    stat_ch boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status = 'active' AND NEW.platform_role = 'user' THEN
            NEW.platform_role := CASE WHEN NEW.role = 'admin' THEN 'admin' ELSE 'user' END;
            IF NEW.role = 'suspended' THEN NEW.status := 'suspended'; END IF;
        ELSIF NEW.role = 'member' THEN
            NEW.role := CASE WHEN NEW.status = 'suspended' THEN 'suspended' WHEN NEW.platform_role = 'admin' THEN 'admin' ELSE 'member' END;
        END IF;
    ELSE
        role_ch := NEW.role IS DISTINCT FROM OLD.role;
        plat_ch := NEW.platform_role IS DISTINCT FROM OLD.platform_role;
        stat_ch := NEW.status IS DISTINCT FROM OLD.status;
        IF role_ch AND NOT plat_ch AND NOT stat_ch THEN
            NEW.platform_role := CASE WHEN NEW.role = 'admin' THEN 'admin' ELSE 'user' END;
            IF NEW.role = 'suspended' THEN
                NEW.status := 'suspended';
            ELSIF OLD.status <> 'deleted' THEN
                NEW.status := 'active';
            END IF;
        ELSIF (plat_ch OR stat_ch) AND NOT role_ch THEN
            IF NEW.status = 'suspended' THEN
                NEW.role := 'suspended';
            ELSIF NEW.status = 'active' THEN
                NEW.role := CASE WHEN NEW.platform_role = 'admin' THEN 'admin' ELSE 'member' END;
            END IF;
        END IF;
        IF (role_ch OR plat_ch OR stat_ch) AND NEW.access_epoch = OLD.access_epoch THEN
            NEW.access_epoch := OLD.access_epoch + 1;
        END IF;
    END IF;
    IF NEW.role NOT IN ('admin', 'member', 'suspended')
       AND (TG_OP = 'INSERT' OR NEW.role IS DISTINCT FROM OLD.role) THEN
        INSERT INTO access_anomalies (kind, user_id, detail) VALUES ('users.role.unknown', NEW.id, NEW.role);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_access_sync ON users;
CREATE TRIGGER users_access_sync BEFORE INSERT OR UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION access_trg_users_sync();

CREATE OR REPLACE FUNCTION access_trg_users_notify() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('capsule_access', om.org_id::text) FROM org_members om WHERE om.user_id = NEW.id;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_access_notify ON users;
CREATE TRIGGER users_access_notify AFTER UPDATE ON users
    FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status OR OLD.platform_role IS DISTINCT FROM NEW.platform_role)
    EXECUTE FUNCTION access_trg_users_notify();

-- ---------------------------------------------------------------- org_members.role <-> template_id
CREATE OR REPLACE FUNCTION access_trg_org_members_sync() RETURNS trigger AS $$
DECLARE
    t_slug   text;
    t_system boolean;
    role_ch  boolean;
    tpl_ch   boolean;
BEGIN
    IF NEW.template_id IS NOT NULL THEN
        SELECT slug, system INTO t_slug, t_system FROM role_templates
         WHERE id = NEW.template_id AND kind = 'org' AND (org_id IS NULL OR org_id = NEW.org_id);
        IF NOT FOUND THEN
            RAISE EXCEPTION 'template % is not an organization template of %', NEW.template_id, NEW.org_id USING ERRCODE = 'check_violation';
        END IF;
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.template_id IS NULL THEN
            SELECT id INTO NEW.template_id FROM role_templates WHERE system AND kind = 'org' AND slug = NEW.role;
        ELSIF t_system THEN
            NEW.role := t_slug;
        END IF;
    ELSE
        role_ch := NEW.role IS DISTINCT FROM OLD.role;
        tpl_ch  := NEW.template_id IS DISTINCT FROM OLD.template_id;
        IF role_ch AND NOT tpl_ch THEN
            NEW.template_id := NULL;
            SELECT id INTO NEW.template_id FROM role_templates WHERE system AND kind = 'org' AND slug = NEW.role;
            NEW.template_version := NULL;
        ELSIF tpl_ch AND NOT role_ch THEN
            IF t_system THEN NEW.role := t_slug; END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS org_members_access_sync ON org_members;
CREATE TRIGGER org_members_access_sync BEFORE INSERT OR UPDATE ON org_members
    FOR EACH ROW EXECUTE FUNCTION access_trg_org_members_sync();

CREATE OR REPLACE FUNCTION access_trg_org_members_bump() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM access_bump_org(OLD.org_id);
    ELSIF TG_OP = 'INSERT' OR NEW.role IS DISTINCT FROM OLD.role OR NEW.template_id IS DISTINCT FROM OLD.template_id
          OR NEW.template_version IS DISTINCT FROM OLD.template_version OR NEW.status IS DISTINCT FROM OLD.status THEN
        PERFORM access_bump_org(NEW.org_id);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS org_members_access_bump ON org_members;
CREATE TRIGGER org_members_access_bump AFTER INSERT OR UPDATE OR DELETE ON org_members
    FOR EACH ROW EXECUTE FUNCTION access_trg_org_members_bump();

-- ---------------------------------------------------------------- project_members <-> access_assignments
-- Solo se espeja lo expresable en el modelo viejo: asignaciones directas de usuario, alcance proyecto, plantilla de proyecto del
-- sistema (admin|deployer|viewer), fuente migrated o legacy-api, no revocadas. Lo demas (grupos, manual, repo, entorno) no existe
-- en project_members. La caducidad no se espeja: el barrido (P5) revoca y la revocacion si se espeja.

CREATE OR REPLACE FUNCTION access_mirror_to_assignment(p_project uuid, p_user uuid) RETURNS void AS $$
DECLARE
    v_org  uuid;
    v_role text;
    v_by   uuid;
    v_at   timestamptz;
    v_tpl  uuid;
BEGIN
    SELECT org_id INTO v_org FROM projects WHERE id = p_project;
    IF v_org IS NULL THEN
        RETURN; -- proyecto borrado: access_purge_projects limpia las asignaciones
    END IF;
    SELECT role, created_by, created_at INTO v_role, v_by, v_at FROM project_members WHERE project_id = p_project AND user_id = p_user;
    IF v_role IS NULL THEN
        UPDATE access_assignments SET revoked_at = now()
         WHERE subject_type = 'user' AND subject_id = p_user AND scope_type = 'project' AND scope_id = p_project
           AND revoked_at IS NULL AND source IN ('migrated', 'legacy-api')
           AND template_id IN (SELECT id FROM role_templates WHERE system AND kind = 'project');
        RETURN;
    END IF;
    v_tpl := access_system_template_id('project', v_role);
    UPDATE access_assignments SET revoked_at = now()
     WHERE subject_type = 'user' AND subject_id = p_user AND scope_type = 'project' AND scope_id = p_project
       AND revoked_at IS NULL AND source IN ('migrated', 'legacy-api') AND template_id <> v_tpl
       AND template_id IN (SELECT id FROM role_templates WHERE system AND kind = 'project');
    IF NOT EXISTS (SELECT 1 FROM access_assignments
                    WHERE subject_type = 'user' AND subject_id = p_user AND scope_type = 'project' AND scope_id = p_project
                      AND template_id = v_tpl AND revoked_at IS NULL) THEN
        INSERT INTO access_assignments (org_id, subject_type, subject_id, scope_type, scope_id, template_id, source, created_by, created_at)
        VALUES (v_org, 'user', p_user, 'project', p_project, v_tpl, 'legacy-api', v_by, v_at);
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION access_mirror_to_project_member(p_project uuid, p_user uuid) RETURNS void AS $$
DECLARE
    v_role text;
    v_by   uuid;
    v_at   timestamptz;
BEGIN
    SELECT t.slug, a.created_by, a.created_at INTO v_role, v_by, v_at
      FROM access_assignments a JOIN role_templates t ON t.id = a.template_id
     WHERE a.subject_type = 'user' AND a.subject_id = p_user AND a.scope_type = 'project' AND a.scope_id = p_project
       AND a.revoked_at IS NULL AND a.source IN ('migrated', 'legacy-api')
       AND t.system AND t.kind = 'project' AND t.slug IN ('admin', 'deployer', 'viewer')
     ORDER BY CASE t.slug WHEN 'admin' THEN 1 WHEN 'deployer' THEN 2 ELSE 3 END, a.created_at
     LIMIT 1;
    IF NOT FOUND THEN
        DELETE FROM project_members WHERE project_id = p_project AND user_id = p_user;
    ELSIF EXISTS (SELECT 1 FROM projects WHERE id = p_project) AND EXISTS (SELECT 1 FROM users WHERE id = p_user) THEN
        INSERT INTO project_members (project_id, user_id, role, created_by, created_at)
        VALUES (p_project, p_user, v_role, v_by, v_at)
        ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role;
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION access_trg_pm_to_assign() RETURNS trigger AS $$
DECLARE
    v_org uuid;
BEGIN
    IF access_sync_busy() THEN
        RETURN NULL;
    END IF;
    PERFORM set_config('capsule.access_sync', 'on', true);
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        PERFORM access_mirror_to_assignment(OLD.project_id, OLD.user_id);
        SELECT org_id INTO v_org FROM projects WHERE id = OLD.project_id;
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        PERFORM access_mirror_to_assignment(NEW.project_id, NEW.user_id);
        SELECT org_id INTO v_org FROM projects WHERE id = NEW.project_id;
    END IF;
    PERFORM set_config('capsule.access_sync', '', true);
    IF v_org IS NOT NULL THEN
        PERFORM access_bump_org(v_org);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS project_members_access_sync ON project_members;
CREATE TRIGGER project_members_access_sync AFTER INSERT OR UPDATE OR DELETE ON project_members
    FOR EACH ROW EXECUTE FUNCTION access_trg_pm_to_assign();

CREATE OR REPLACE FUNCTION access_assignment_mirrored(a access_assignments) RETURNS boolean AS $$
    SELECT a.subject_type = 'user' AND a.scope_type = 'project' AND a.source IN ('migrated', 'legacy-api')
       AND EXISTS (SELECT 1 FROM role_templates t WHERE t.id = a.template_id AND t.system AND t.kind = 'project'
                   AND t.slug IN ('admin', 'deployer', 'viewer'));
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION access_trg_assign_to_pm() RETURNS trigger AS $$
BEGIN
    IF access_sync_busy() THEN
        RETURN NULL;
    END IF;
    PERFORM set_config('capsule.access_sync', 'on', true);
    IF TG_OP IN ('UPDATE', 'DELETE') AND access_assignment_mirrored(OLD) THEN
        PERFORM access_mirror_to_project_member(OLD.scope_id, OLD.subject_id);
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') AND access_assignment_mirrored(NEW) THEN
        PERFORM access_mirror_to_project_member(NEW.scope_id, NEW.subject_id);
    END IF;
    PERFORM set_config('capsule.access_sync', '', true);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS access_assignments_sync ON access_assignments;
CREATE TRIGGER access_assignments_sync AFTER INSERT OR UPDATE OR DELETE ON access_assignments
    FOR EACH ROW EXECUTE FUNCTION access_trg_assign_to_pm();
