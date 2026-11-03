-- Git Capsule A4: reglas de proteccion de rama (fuente de verdad; se proyectan a Forgejo).
-- Valores por defecto seguros: PR obligatorio, forzado y borrado bloqueados, tambien para administradores.
CREATE TABLE IF NOT EXISTS branch_protection_rules (
    id                        uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id                uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    pattern                   varchar(255) NOT NULL,
    require_pull_request      boolean      NOT NULL DEFAULT true,
    required_approvals        int          NOT NULL DEFAULT 0,
    dismiss_stale_approvals   boolean      NOT NULL DEFAULT true,
    block_on_rejected_reviews boolean      NOT NULL DEFAULT true,
    require_code_owner_review boolean      NOT NULL DEFAULT false,
    required_checks           text[]       NOT NULL DEFAULT '{}',
    require_up_to_date        boolean      NOT NULL DEFAULT false,
    require_signed_commits    boolean      NOT NULL DEFAULT false,
    require_linear_history    boolean      NOT NULL DEFAULT false,
    block_force_push          boolean      NOT NULL DEFAULT true,
    block_deletion            boolean      NOT NULL DEFAULT true,
    push_allow_roles          text[]       NOT NULL DEFAULT '{}',
    merge_allow_roles         text[]       NOT NULL DEFAULT '{}',
    enforce_for_admins        boolean      NOT NULL DEFAULT true,
    block_on_security_policy  boolean      NOT NULL DEFAULT false,
    delete_branch_on_merge    boolean      NOT NULL DEFAULT false,
    created_by                uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at                timestamptz  NOT NULL DEFAULT now(),
    updated_at                timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_branch_protection_pattern UNIQUE (project_id, pattern),
    CONSTRAINT chk_branch_protection_approvals CHECK (required_approvals BETWEEN 0 AND 10),
    CONSTRAINT chk_branch_protection_pattern CHECK (length(pattern) BETWEEN 1 AND 255)
);
CREATE INDEX IF NOT EXISTS idx_branch_protection_project ON branch_protection_rules(project_id, created_at);
