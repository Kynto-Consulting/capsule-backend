-- Gateway: tokens de servicio `cgs_` (agentes, CI, aplicaciones). PROTOCOL 11.1.
-- Alcance: un proyecto y, opcionalmente, un servicio; solo project.connect. Expiracion obligatoria (<= 90 dias).
-- El valor del token NUNCA se guarda: solo su SHA-256 (hex).
CREATE TABLE IF NOT EXISTS gateway_service_tokens (
    id           uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id   uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    service_id   uuid         REFERENCES gateway_services(id) ON DELETE CASCADE,
    name         varchar(100) NOT NULL,
    token_hash   varchar(64)  NOT NULL,
    prefix       varchar(12)  NOT NULL,
    created_by   uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz  NOT NULL DEFAULT now(),
    expires_at   timestamptz  NOT NULL,
    revoked_at   timestamptz,
    last_used_at timestamptz,
    CONSTRAINT ck_gateway_service_tokens_expiry CHECK (expires_at > created_at AND expires_at <= created_at + interval '91 days')
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_gateway_service_tokens_hash ON gateway_service_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_gateway_service_tokens_project ON gateway_service_tokens (project_id) WHERE revoked_at IS NULL;
