-- Per-database external access rules (applied to the host security group by the API).
CREATE TABLE IF NOT EXISTS database_access_rules (
    id          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id uuid         NOT NULL REFERENCES databases(id) ON DELETE CASCADE,
    cidr        varchar(18)  NOT NULL,
    description text         NOT NULL DEFAULT '',
    created_by  uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_database_access_rules_db_cidr UNIQUE (database_id, cidr)
);
CREATE INDEX IF NOT EXISTS idx_database_access_rules_db ON database_access_rules(database_id);

-- Per-project application IP allowlist (CIDRs). Empty = public.
ALTER TABLE projects ADD COLUMN IF NOT EXISTS ip_allowlist text[] NOT NULL DEFAULT '{}';
