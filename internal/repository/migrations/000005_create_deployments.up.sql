BEGIN;

CREATE TABLE deployments (
    id                  uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id          uuid         NOT NULL REFERENCES projects(id),
    server_id           uuid         REFERENCES servers(id),
    version             varchar(50)  NOT NULL,
    git_sha             varchar(40),
    status              varchar(30)  NOT NULL DEFAULT 'pending',
    image_tag           varchar(200),
    build_strategy      varchar(30),
    container_port      int,
    build_duration_ms   bigint,
    deploy_duration_ms  bigint,
    trigger             varchar(30)  NOT NULL DEFAULT 'manual',
    triggered_by        uuid         REFERENCES users(id),
    started_at          timestamptz,
    completed_at        timestamptz,
    created_at          timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE build_logs (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id uuid        NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    level         varchar(10) NOT NULL DEFAULT 'info',
    message       text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_deployments_project        ON deployments(project_id);
CREATE INDEX idx_deployments_project_status ON deployments(project_id, status);
CREATE INDEX idx_deployments_created        ON deployments(created_at DESC);
CREATE INDEX idx_deployments_server         ON deployments(server_id) WHERE server_id IS NOT NULL;
CREATE INDEX idx_build_logs_deployment      ON build_logs(deployment_id, created_at);

COMMIT;
