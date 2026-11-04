-- Plantillas y versiones inmutables (SPEC 4 y 14). El catalogo vive en codigo, no aqui.

CREATE OR REPLACE FUNCTION access_perms_valid(p text[]) RETURNS boolean AS $$
    SELECT p IS NULL OR (cardinality(p) <= 200 AND NOT EXISTS (
        SELECT 1 FROM unnest(p) AS x WHERE x IS NULL OR x !~ '^(\*|[a-z][a-z0-9-]*:([a-z][a-z0-9-]*|\*))$'));
$$ LANGUAGE sql IMMUTABLE;

CREATE TABLE IF NOT EXISTS role_templates (
    id              uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid         REFERENCES organizations(id) ON DELETE CASCADE,
    kind            varchar(10)  NOT NULL,
    slug            varchar(40)  NOT NULL,
    name            varchar(100) NOT NULL,
    description     text         NOT NULL DEFAULT '',
    system          boolean      NOT NULL DEFAULT false,
    cloned_from     uuid         REFERENCES role_templates(id) ON DELETE SET NULL,
    current_version int          NOT NULL DEFAULT 1,
    archived_at     timestamptz,
    created_by      uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz  NOT NULL DEFAULT now(),
    updated_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_role_templates_kind   CHECK (kind IN ('org', 'project', 'repo')),
    CONSTRAINT chk_role_templates_slug   CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,39}$'),
    CONSTRAINT chk_role_templates_system CHECK (system = (org_id IS NULL)),
    CONSTRAINT chk_role_templates_ver    CHECK (current_version >= 1)
);
-- UNIQUE NULLS NOT DISTINCT exige Postgres 15: dos indices parciales dan lo mismo en cualquier version.
CREATE UNIQUE INDEX IF NOT EXISTS uq_role_templates_org_slug ON role_templates(org_id, kind, slug) WHERE org_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_role_templates_sys_slug ON role_templates(kind, slug) WHERE org_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_role_templates_org ON role_templates(org_id) WHERE org_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS role_template_versions (
    template_id       uuid        NOT NULL REFERENCES role_templates(id) ON DELETE CASCADE,
    version           int         NOT NULL,
    permissions       text[]      NOT NULL DEFAULT '{}',
    ceiling           text[],
    ceiling_project   text[],
    floor_template_id uuid        REFERENCES role_templates(id),
    base_template_id  uuid        REFERENCES role_templates(id),
    note              text        NOT NULL DEFAULT '',
    created_by        uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (template_id, version),
    CONSTRAINT chk_rtv_version CHECK (version >= 1),
    CONSTRAINT chk_rtv_perms   CHECK (access_perms_valid(permissions)),
    CONSTRAINT chk_rtv_ceiling CHECK (access_perms_valid(ceiling)),
    CONSTRAINT chk_rtv_ceilingp CHECK (access_perms_valid(ceiling_project))
);

-- Una version publicada no cambia jamas. Solo se permite borrarla cuando su plantilla ya no existe (cascada al borrar la organizacion).
CREATE OR REPLACE FUNCTION access_trg_version_immutable() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' AND NOT EXISTS (SELECT 1 FROM role_templates WHERE id = OLD.template_id) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'role_template_versions rows are immutable (% on %/%)', TG_OP, OLD.template_id, OLD.version
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS role_template_versions_immutable ON role_template_versions;
CREATE TRIGGER role_template_versions_immutable BEFORE UPDATE OR DELETE ON role_template_versions
    FOR EACH ROW EXECUTE FUNCTION access_trg_version_immutable();

-- Plantillas del sistema: nadie las borra ni cambia su identidad; solo avanza current_version (migracion de datos) y updated_at.
CREATE OR REPLACE FUNCTION access_trg_template_system() RETURNS trigger AS $$
BEGIN
    IF OLD.system THEN
        IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'system role template % cannot be deleted', OLD.slug USING ERRCODE = 'restrict_violation';
        END IF;
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.kind <> OLD.kind
           OR NEW.slug <> OLD.slug OR NEW.system <> OLD.system OR NEW.archived_at IS DISTINCT FROM OLD.archived_at
           OR NEW.current_version < OLD.current_version THEN
            RAISE EXCEPTION 'system role template % is immutable', OLD.slug USING ERRCODE = 'restrict_violation';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS role_templates_system_guard ON role_templates;
CREATE TRIGGER role_templates_system_guard BEFORE UPDATE OR DELETE ON role_templates
    FOR EACH ROW EXECUTE FUNCTION access_trg_template_system();
