BEGIN;

CREATE TABLE execution_logs (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    uuid        NOT NULL REFERENCES projects(id),
    source        varchar(50) NOT NULL, -- 'runtime', 'lambda', 'worker', 'cron'
    source_id     varchar(200),         -- container name, function name, worker id, cron id
    level         varchar(20) NOT NULL DEFAULT 'info',
    message       text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_execution_logs_project ON execution_logs(project_id, created_at DESC);
CREATE INDEX idx_execution_logs_source  ON execution_logs(source, source_id, created_at DESC);

COMMIT;
