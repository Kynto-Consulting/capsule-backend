-- Git Capsule A6: historial por entorno (un intento por promocion; espeja su estado).
-- status: pending_approval|waiting|queued|deploying|success|failed|rejected|cancelled|expired
-- (la promocion "approved" se muestra como "queued").
CREATE TABLE IF NOT EXISTS environment_deployments (
    id              uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id  uuid         NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    promotion_id    uuid         NOT NULL REFERENCES promotions(id) ON DELETE CASCADE,
    sha             varchar(64)  NOT NULL,
    deployment_id   uuid         REFERENCES deployments(id) ON DELETE SET NULL,
    status          varchar(20)  NOT NULL,
    health_status   varchar(20)  NOT NULL DEFAULT '',
    created_at      timestamptz  NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    CONSTRAINT uq_environment_deployments_promotion UNIQUE (promotion_id)
);
CREATE INDEX IF NOT EXISTS idx_environment_deployments_env ON environment_deployments(environment_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_environment_deployments_sha ON environment_deployments(environment_id, sha, status);
