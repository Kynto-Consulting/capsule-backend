BEGIN;

CREATE TABLE servers (
    id                  uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    name                varchar(100) NOT NULL,
    instance_id         varchar(50)  UNIQUE,
    instance_type       varchar(30),
    availability_zone   varchar(20),
    public_ip           inet,
    private_ip          inet,
    status              varchar(30)  NOT NULL DEFAULT 'provisioning',
    role                varchar(30)  NOT NULL DEFAULT 'worker',
    metadata            jsonb        NOT NULL DEFAULT '{}',
    last_heartbeat_at   timestamptz,
    created_at          timestamptz  NOT NULL DEFAULT now(),
    updated_at          timestamptz  NOT NULL DEFAULT now(),
    deleted_at          timestamptz
);

CREATE INDEX idx_servers_status ON servers(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_servers_role   ON servers(role)   WHERE deleted_at IS NULL;

COMMIT;
