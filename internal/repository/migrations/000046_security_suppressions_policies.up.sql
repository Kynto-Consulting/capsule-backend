-- Git Capsule B7: supresiones de alertas de seguridad y politica por proyecto.
-- Supresion: motivo enumerado, justificacion >= 10 caracteres y caducidad obligatoria (el maximo de dias lo hace cumplir el servicio).
CREATE TABLE IF NOT EXISTS security_suppressions (
    id                   uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id           uuid          NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    rule_id              varchar(255)  NOT NULL DEFAULT '',
    fingerprint          varchar(64)   NOT NULL DEFAULT '',
    path_glob            varchar(512)  NOT NULL DEFAULT '',
    reason               varchar(24)   NOT NULL,
    justification        text          NOT NULL,
    expires_at           timestamptz   NOT NULL,
    state                varchar(12)   NOT NULL DEFAULT 'active',
    source               varchar(12)   NOT NULL DEFAULT 'manual',
    alert_id             uuid,
    covers_high          boolean       NOT NULL DEFAULT false,
    created_by           uuid          REFERENCES users(id) ON DELETE SET NULL,
    created_at           timestamptz   NOT NULL DEFAULT now(),
    revoked_at           timestamptz,
    revoked_by           uuid          REFERENCES users(id) ON DELETE SET NULL,
    notified_expiring_at timestamptz,
    CONSTRAINT chk_supp_reason CHECK (reason IN ('false_positive','wont_fix','used_in_tests','risk_accepted')),
    CONSTRAINT chk_supp_state CHECK (state IN ('active','expired','revoked')),
    CONSTRAINT chk_supp_source CHECK (source IN ('manual','alert')),
    CONSTRAINT chk_supp_justification CHECK (char_length(btrim(justification)) >= 10),
    CONSTRAINT chk_supp_match CHECK (rule_id <> '' OR fingerprint <> '' OR path_glob <> ''),
    CONSTRAINT chk_supp_glob CHECK (path_glob = '' OR btrim(translate(path_glob, '*/', '')) <> '')
);
CREATE INDEX IF NOT EXISTS idx_security_supp_project ON security_suppressions(project_id, state, expires_at);
CREATE INDEX IF NOT EXISTS idx_security_supp_fp ON security_suppressions(project_id, fingerprint) WHERE fingerprint <> '';

CREATE TABLE IF NOT EXISTS security_policies (
    project_id             uuid         PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    block_merge_dependency varchar(8)   NOT NULL DEFAULT 'high',
    block_merge_code       varchar(8)   NOT NULL DEFAULT 'high',
    block_merge_secret     varchar(8)   NOT NULL DEFAULT 'any',
    block_deploy_on        varchar(8)   NOT NULL DEFAULT 'critical',
    required_tools         text[]       NOT NULL DEFAULT '{}',
    max_suppression_days   int          NOT NULL DEFAULT 180,
    applies_to_branches    text[]       NOT NULL DEFAULT '{}',
    updated_by             uuid         REFERENCES users(id) ON DELETE SET NULL,
    updated_at             timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_secpol_dep CHECK (block_merge_dependency IN ('off','critical','high','medium','low')),
    CONSTRAINT chk_secpol_code CHECK (block_merge_code IN ('off','critical','high','medium','low')),
    CONSTRAINT chk_secpol_secret CHECK (block_merge_secret IN ('off','any')),
    CONSTRAINT chk_secpol_deploy CHECK (block_deploy_on IN ('off','critical','high')),
    CONSTRAINT chk_secpol_days CHECK (max_suppression_days BETWEEN 1 AND 365)
);
