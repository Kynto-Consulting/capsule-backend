-- Git Capsule A6: promociones (solicitud de desplegar un SHA a un entorno) y sus decisiones.
-- Estados: pending_approval|waiting|approved|deploying|success|failed|rejected|cancelled|expired.
CREATE TABLE IF NOT EXISTS promotions (
    id                    uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id            uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_id        uuid         NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    sha                   varchar(64)  NOT NULL,
    branch                varchar(255) NOT NULL DEFAULT '',
    from_environment      varchar(31)  NOT NULL DEFAULT '',
    comment               text         NOT NULL DEFAULT '',
    status                varchar(20)  NOT NULL DEFAULT 'pending_approval',
    status_reason         text         NOT NULL DEFAULT '',
    requested_by          uuid         REFERENCES users(id) ON DELETE SET NULL,
    required_approvals    int          NOT NULL DEFAULT 0,
    quorum_at             timestamptz,
    not_before            timestamptz,
    expires_at            timestamptz  NOT NULL,
    idempotency_key       varchar(128) NOT NULL DEFAULT '',
    source_deployment_id  uuid,
    deployment_id         uuid,
    checks                jsonb        NOT NULL DEFAULT '{}'::jsonb,
    conditions            jsonb        NOT NULL DEFAULT '[]'::jsonb,
    started_at            timestamptz,
    finished_at           timestamptz,
    created_at            timestamptz  NOT NULL DEFAULT now(),
    updated_at            timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_promotions_status CHECK (status IN
        ('pending_approval','waiting','approved','deploying','success','failed','rejected','cancelled','expired'))
);
CREATE INDEX IF NOT EXISTS idx_promotions_env_status ON promotions(environment_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_promotions_project ON promotions(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_promotions_expiry ON promotions(expires_at)
    WHERE status IN ('pending_approval','waiting','approved');
-- Idempotency-Key: la misma clave del mismo solicitante en el mismo proyecto es la misma promocion.
CREATE UNIQUE INDEX IF NOT EXISTS uq_promotions_idempotency ON promotions(project_id, requested_by, idempotency_key)
    WHERE idempotency_key <> '';
-- Cola por entorno: como mucho un despliegue en curso por entorno.
CREATE UNIQUE INDEX IF NOT EXISTS uq_promotions_one_deploying ON promotions(environment_id)
    WHERE status = 'deploying';
-- No se duplica una promocion activa del mismo SHA al mismo entorno.
CREATE UNIQUE INDEX IF NOT EXISTS uq_promotions_active_sha ON promotions(environment_id, sha)
    WHERE status IN ('pending_approval','waiting','approved','deploying');

CREATE TABLE IF NOT EXISTS promotion_approvals (
    id              uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    promotion_id    uuid         NOT NULL REFERENCES promotions(id) ON DELETE CASCADE,
    user_id         uuid         REFERENCES users(id) ON DELETE SET NULL,
    decision        varchar(10)  NOT NULL,
    comment         text         NOT NULL DEFAULT '',
    self_approval   boolean      NOT NULL DEFAULT false,
    role_at_decision varchar(16) NOT NULL DEFAULT '',
    created_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT chk_promotion_approvals_decision CHECK (decision IN ('approved','rejected')),
    CONSTRAINT uq_promotion_approvals_user UNIQUE (promotion_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_promotion_approvals_promotion ON promotion_approvals(promotion_id, created_at);
