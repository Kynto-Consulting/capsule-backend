-- Git Capsule B7: alertas de seguridad (dependency|code|secret). Para las de tipo secreto NUNCA se guarda el valor:
-- solo huella (HMAC), ruta, linea y regla; evidence queda vacio (lo exige un CHECK).
CREATE TABLE IF NOT EXISTS security_alerts (
    id                    uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id            uuid          NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind                  varchar(12)   NOT NULL,
    tool                  varchar(20)   NOT NULL,
    tool_name             varchar(64)   NOT NULL,
    rule_id               varchar(255)  NOT NULL,
    severity              varchar(8)    NOT NULL,
    state                 varchar(12)   NOT NULL DEFAULT 'open',
    title                 varchar(300)  NOT NULL,
    description           text          NOT NULL DEFAULT '',
    fingerprint           varchar(64)   NOT NULL,
    branch                varchar(255)  NOT NULL,
    path                  varchar(1024) NOT NULL DEFAULT '',
    start_line            int           NOT NULL DEFAULT 0,
    end_line              int           NOT NULL DEFAULT 0,
    package_name          varchar(255)  NOT NULL DEFAULT '',
    package_version       varchar(128)  NOT NULL DEFAULT '',
    fixed_version         varchar(128)  NOT NULL DEFAULT '',
    advisory              varchar(255)  NOT NULL DEFAULT '',
    evidence              text          NOT NULL DEFAULT '',
    trace                 jsonb         NOT NULL DEFAULT '[]',
    first_seen_sha        varchar(64)   NOT NULL DEFAULT '',
    last_seen_sha         varchar(64)   NOT NULL DEFAULT '',
    last_upload_id        uuid,
    suppression_id        uuid          REFERENCES security_suppressions(id) ON DELETE SET NULL,
    dismiss_reason        varchar(24)   NOT NULL DEFAULT '',
    dismiss_justification text          NOT NULL DEFAULT '',
    dismissed_by          uuid          REFERENCES users(id) ON DELETE SET NULL,
    dismiss_expires_at    timestamptz,
    dismissed_at          timestamptz,
    fixed_at              timestamptz,
    created_at            timestamptz   NOT NULL DEFAULT now(),
    updated_at            timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT uq_security_alert UNIQUE (project_id, tool_name, branch, fingerprint),
    CONSTRAINT chk_secalert_kind CHECK (kind IN ('dependency','code','secret')),
    CONSTRAINT chk_secalert_tool CHECK (tool IN ('osv-scanner','renovate','semgrep','gosec','bandit','eslint-security','gitleaks','trivy','sarif-other')),
    CONSTRAINT chk_secalert_sev CHECK (severity IN ('critical','high','medium','low','info')),
    CONSTRAINT chk_secalert_state CHECK (state IN ('open','fixed','dismissed')),
    CONSTRAINT chk_secalert_dismissed CHECK (state <> 'dismissed' OR dismiss_expires_at IS NOT NULL),
    CONSTRAINT chk_secalert_secret_no_evidence CHECK (kind <> 'secret' OR evidence = '')
);
CREATE INDEX IF NOT EXISTS idx_secalert_list ON security_alerts(project_id, state, severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_secalert_branch_sha ON security_alerts(project_id, branch, last_seen_sha);
CREATE INDEX IF NOT EXISTS idx_secalert_fp ON security_alerts(project_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_secalert_expiry ON security_alerts(dismiss_expires_at) WHERE state = 'dismissed';
