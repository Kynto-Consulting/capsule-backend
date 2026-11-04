-- Grupos planos y asignaciones (SPEC 5.2, 6 y 14). Un grupo no tiene permisos propios: recibe asignaciones.

CREATE TABLE IF NOT EXISTS groups (
    id           uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug         varchar(40)  NOT NULL,
    name         varchar(100) NOT NULL,
    description  text         NOT NULL DEFAULT '',
    source       varchar(10)  NOT NULL DEFAULT 'manual',
    external_ref text         NOT NULL DEFAULT '',
    archived_at  timestamptz,
    created_by   uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_groups_org_slug UNIQUE (org_id, slug),
    CONSTRAINT chk_groups_slug    CHECK (slug ~ '^[a-z0-9-]{1,40}$'),
    CONSTRAINT chk_groups_source  CHECK (source IN ('manual', 'oidc'))
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id   uuid        NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    source     varchar(10) NOT NULL DEFAULT 'manual',
    added_by   uuid        REFERENCES users(id) ON DELETE SET NULL,
    added_at   timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    PRIMARY KEY (group_id, user_id),
    CONSTRAINT chk_group_members_source CHECK (source IN ('manual', 'oidc'))
);
-- usuario -> grupos al compilar el snapshot
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);

CREATE TABLE IF NOT EXISTS access_assignments (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    subject_type   varchar(8)  NOT NULL,
    subject_id     uuid        NOT NULL,
    scope_type     varchar(8)  NOT NULL,
    scope_id       uuid        NOT NULL,
    template_id    uuid        NOT NULL REFERENCES role_templates(id),
    pinned_version int,
    source         varchar(12) NOT NULL DEFAULT 'manual',
    reason         text        NOT NULL DEFAULT '',
    expires_at     timestamptz,
    created_by     uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    revoked_at     timestamptz,
    revoked_by     uuid        REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT chk_access_assign_subject CHECK (subject_type IN ('user', 'group')),
    CONSTRAINT chk_access_assign_scope   CHECK (scope_type IN ('org', 'project', 'repo', 'env')),
    CONSTRAINT chk_access_assign_source  CHECK (source IN ('manual', 'migrated', 'legacy-api', 'approver', 'oidc', 'temporary')),
    CONSTRAINT chk_access_assign_pin     CHECK (pinned_version IS NULL OR pinned_version >= 1),
    CONSTRAINT chk_access_assign_orgscope CHECK (scope_type <> 'org' OR scope_id = org_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_assign_live
    ON access_assignments(subject_type, subject_id, scope_type, scope_id, template_id) WHERE revoked_at IS NULL;
-- compilacion del snapshot (usuario directo y grupos del usuario)
CREATE INDEX IF NOT EXISTS idx_access_assign_subject ON access_assignments(org_id, subject_type, subject_id) WHERE revoked_at IS NULL;
-- "quien tiene acceso a X"
CREATE INDEX IF NOT EXISTS idx_access_assign_scope   ON access_assignments(scope_type, scope_id) WHERE revoked_at IS NULL;
-- barrido de caducidades
CREATE INDEX IF NOT EXISTS idx_access_assign_expiry  ON access_assignments(expires_at) WHERE revoked_at IS NULL AND expires_at IS NOT NULL;
-- borrar una plantilla exige cero asignaciones
CREATE INDEX IF NOT EXISTS idx_access_assign_template ON access_assignments(template_id);

-- La organizacion del alcance, del sujeto y de la plantilla debe coincidir con org_id (confused deputy, SPEC 13.2 y 13.4).
CREATE OR REPLACE FUNCTION access_trg_assignment_check() RETURNS trigger AS $$
DECLARE
    t_org  uuid;
    t_kind text;
    ok     boolean;
BEGIN
    IF NEW.scope_type IN ('project', 'repo') THEN
        SELECT EXISTS (SELECT 1 FROM projects WHERE id = NEW.scope_id AND org_id = NEW.org_id) INTO ok;
    ELSIF NEW.scope_type = 'env' THEN
        SELECT EXISTS (SELECT 1 FROM environments e JOIN projects p ON p.id = e.project_id
                        WHERE e.id = NEW.scope_id AND p.org_id = NEW.org_id) INTO ok;
    ELSE
        ok := (NEW.scope_id = NEW.org_id);
    END IF;
    IF NOT ok THEN
        RAISE EXCEPTION 'assignment scope %/% does not belong to organization %', NEW.scope_type, NEW.scope_id, NEW.org_id
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.subject_type = 'group' AND NOT EXISTS (SELECT 1 FROM groups WHERE id = NEW.subject_id AND org_id = NEW.org_id) THEN
        RAISE EXCEPTION 'group % does not belong to organization %', NEW.subject_id, NEW.org_id USING ERRCODE = 'check_violation';
    END IF;
    SELECT org_id, kind INTO t_org, t_kind FROM role_templates WHERE id = NEW.template_id;
    IF t_org IS NOT NULL AND t_org <> NEW.org_id THEN
        RAISE EXCEPTION 'template % belongs to another organization', NEW.template_id USING ERRCODE = 'check_violation';
    END IF;
    IF NOT ((NEW.scope_type = 'repo' AND t_kind IN ('repo', 'project')) OR (NEW.scope_type <> 'repo' AND t_kind = 'project')) THEN
        RAISE EXCEPTION 'template kind % cannot be assigned at scope %', t_kind, NEW.scope_type USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS access_assignments_check ON access_assignments;
CREATE TRIGGER access_assignments_check BEFORE INSERT OR UPDATE OF org_id, subject_type, subject_id, scope_type, scope_id, template_id
    ON access_assignments FOR EACH ROW EXECUTE FUNCTION access_trg_assignment_check();

-- subject_id y scope_id son polimorficos (sin clave foranea): al borrar el sujeto o el alcance se borran sus asignaciones.
CREATE OR REPLACE FUNCTION access_trg_purge_subject() RETURNS trigger AS $$
BEGIN
    IF TG_TABLE_NAME = 'users' THEN
        DELETE FROM access_assignments WHERE subject_type = 'user' AND subject_id = OLD.id;
    ELSIF TG_TABLE_NAME = 'groups' THEN
        DELETE FROM access_assignments WHERE subject_type = 'group' AND subject_id = OLD.id;
    ELSIF TG_TABLE_NAME = 'projects' THEN
        DELETE FROM access_assignments WHERE scope_type IN ('project', 'repo') AND scope_id = OLD.id;
    ELSIF TG_TABLE_NAME = 'environments' THEN
        DELETE FROM access_assignments WHERE scope_type = 'env' AND scope_id = OLD.id;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS access_purge_users ON users;
CREATE TRIGGER access_purge_users AFTER DELETE ON users FOR EACH ROW EXECUTE FUNCTION access_trg_purge_subject();
DROP TRIGGER IF EXISTS access_purge_groups ON groups;
CREATE TRIGGER access_purge_groups AFTER DELETE ON groups FOR EACH ROW EXECUTE FUNCTION access_trg_purge_subject();
DROP TRIGGER IF EXISTS access_purge_projects ON projects;
CREATE TRIGGER access_purge_projects AFTER DELETE ON projects FOR EACH ROW EXECUTE FUNCTION access_trg_purge_subject();
DROP TRIGGER IF EXISTS access_purge_environments ON environments;
CREATE TRIGGER access_purge_environments AFTER DELETE ON environments FOR EACH ROW EXECUTE FUNCTION access_trg_purge_subject();
