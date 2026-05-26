BEGIN;

CREATE TABLE domains (
    id                 uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id         uuid         NOT NULL REFERENCES projects(id),
    domain_name        varchar(255) NOT NULL,
    record_type        varchar(10)  NOT NULL DEFAULT 'CNAME',
    record_value       text,
    verification_token varchar(100),
    status             varchar(30)  NOT NULL DEFAULT 'pending',
    ssl_enabled        boolean      NOT NULL DEFAULT false,
    dns_provider       varchar(30)  NOT NULL DEFAULT 'route53',
    verified_at        timestamptz,
    created_at         timestamptz  NOT NULL DEFAULT now(),
    updated_at         timestamptz  NOT NULL DEFAULT now(),

    CONSTRAINT uq_domains_name UNIQUE (domain_name)
);

CREATE TABLE ssl_certificates (
    id              uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id       uuid         NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    issuer          varchar(100) NOT NULL,
    serial_number   varchar(100),
    certificate_pem text         NOT NULL,
    private_key_enc bytea        NOT NULL,
    issued_at       timestamptz  NOT NULL,
    expires_at      timestamptz  NOT NULL,
    auto_renew      boolean      NOT NULL DEFAULT true,
    created_at      timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX idx_domains_project ON domains(project_id);
CREATE INDEX idx_domains_status  ON domains(status);

COMMIT;
