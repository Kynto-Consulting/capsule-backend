-- Git Capsule A5: webhooks salientes (HTTP firmado, Slack, Discord, correo) y su cola de entregas.
-- project_id NULL = webhook de organizacion (recibe los eventos de todos sus proyectos).
CREATE TABLE IF NOT EXISTS outbound_webhooks (
    id                     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                 uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id             uuid        REFERENCES projects(id) ON DELETE CASCADE,
    kind                   varchar(10) NOT NULL,
    url_enc                bytea,
    email_to               text[]      NOT NULL DEFAULT '{}',
    events                 text[]      NOT NULL DEFAULT '{}',
    branch_filter          text        NOT NULL DEFAULT '',
    active                 boolean     NOT NULL DEFAULT true,
    disabled_reason        text        NOT NULL DEFAULT '',
    secret_enc             bytea,
    prev_secret_enc        bytea,
    prev_secret_expires_at timestamptz,
    last_delivery_status   int         NOT NULL DEFAULT 0,
    last_delivery_at       timestamptz,
    created_by             uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_outbound_webhooks_kind CHECK (kind IN ('http', 'slack', 'discord', 'email'))
);
CREATE INDEX IF NOT EXISTS idx_outbound_webhooks_project ON outbound_webhooks(project_id) WHERE project_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_outbound_webhooks_org ON outbound_webhooks(org_id);

-- Cada fila es una entrega con id estable (X-Capsule-Delivery). El cuerpo se guarda tal cual se firma.
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id       uuid        NOT NULL REFERENCES outbound_webhooks(id) ON DELETE CASCADE,
    event_id         uuid        REFERENCES git_events(id) ON DELETE SET NULL,
    redelivery_of    uuid,
    event            varchar(60) NOT NULL,
    payload          text        NOT NULL,
    status           varchar(10) NOT NULL DEFAULT 'pending',
    attempt          int         NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    status_code      int         NOT NULL DEFAULT 0,
    duration_ms      int         NOT NULL DEFAULT 0,
    error            text        NOT NULL DEFAULT '',
    response_excerpt text        NOT NULL DEFAULT '',
    request_headers  jsonb       NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now(),
    delivered_at     timestamptz,
    CONSTRAINT chk_webhook_deliveries_status CHECK (status IN ('pending', 'delivered', 'failed', 'abandoned'))
);
-- Un evento genera una sola entrega por webhook (el fan-out puede repetirse sin duplicar).
CREATE UNIQUE INDEX IF NOT EXISTS uq_webhook_deliveries_event ON webhook_deliveries(webhook_id, event_id)
    WHERE event_id IS NOT NULL AND redelivery_of IS NULL;
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due ON webhook_deliveries(next_attempt_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id, created_at DESC);
