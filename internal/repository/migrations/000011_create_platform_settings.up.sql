BEGIN;

CREATE TABLE platform_settings (
    key         varchar(255) PRIMARY KEY,
    value       text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

COMMIT;
