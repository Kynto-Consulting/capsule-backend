-- Permisos atomicos P2 (SPEC 14, MIGRATION F1): columnas de estado, epoch y politica. Aditiva: nada lee todavia estas columnas
-- y users.role se conserva (se sincroniza por trigger en 000071).

ALTER TABLE users ADD COLUMN IF NOT EXISTS status        varchar(10) NOT NULL DEFAULT 'active';
ALTER TABLE users ADD COLUMN IF NOT EXISTS platform_role varchar(10) NOT NULL DEFAULT 'user';
ALTER TABLE users ADD COLUMN IF NOT EXISTS access_epoch  bigint      NOT NULL DEFAULT 0;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_users_status') THEN
        ALTER TABLE users ADD CONSTRAINT chk_users_status CHECK (status IN ('active', 'suspended', 'deleted'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_users_platform_role') THEN
        ALTER TABLE users ADD CONSTRAINT chk_users_platform_role CHECK (platform_role IN ('user', 'admin'));
    END IF;
END $$;

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS access_epoch    bigint NOT NULL DEFAULT 0;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS access_settings jsonb  NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE projects ADD COLUMN IF NOT EXISTS access_override varchar(12);
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_projects_access_override') THEN
        ALTER TABLE projects ADD CONSTRAINT chk_projects_access_override CHECK (access_override IS NULL OR access_override IN ('open', 'restricted'));
    END IF;
END $$;

-- Datos que la migracion no sabe traducir (rol desconocido): se listan para revision. Hoy esas filas no son admin ni suspendidas.
CREATE TABLE IF NOT EXISTS access_anomalies (
    id         bigserial   PRIMARY KEY,
    kind       varchar(40) NOT NULL,
    org_id     uuid,
    user_id    uuid,
    detail     text        NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Backfill de usuarios (MIGRATION sec. 2). Condicionado para que repetir el up no pise cambios posteriores.
UPDATE users SET status = 'suspended' WHERE role = 'suspended' AND status = 'active';
UPDATE users SET platform_role = 'admin' WHERE role = 'admin' AND platform_role = 'user';

INSERT INTO access_anomalies (kind, user_id, detail)
SELECT 'users.role.unknown', u.id, u.role FROM users u
 WHERE u.role NOT IN ('admin', 'member', 'suspended')
   AND NOT EXISTS (SELECT 1 FROM access_anomalies a WHERE a.kind = 'users.role.unknown' AND a.user_id = u.id);
