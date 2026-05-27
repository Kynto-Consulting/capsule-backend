BEGIN;
CREATE TABLE email_logs (
  id          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id  uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  domain      varchar(255) NOT NULL,
  from_addr   varchar(255) NOT NULL,
  to_addr     text         NOT NULL,
  subject     varchar(500) NOT NULL DEFAULT '',
  status      varchar(30)  NOT NULL DEFAULT 'sent',
  message_id  varchar(255),
  created_at  timestamptz  NOT NULL DEFAULT now()
);
CREATE INDEX idx_email_logs_project ON email_logs(project_id, created_at DESC);
COMMIT;
