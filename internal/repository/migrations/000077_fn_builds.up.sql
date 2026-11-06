-- Image builds of functions deployed from source (capsule fn deploy --source / capsule fn build, docs/vpn-connector.md 7b).
-- The deploy worker builds them in the same loop as project deployments (one build at a time on the host) and pushes them
-- to the ECR repository Capsule manages for the function (capsule/fn-<12 hex of the function id>).
CREATE TABLE IF NOT EXISTS fn_builds (
    id          uuid         PRIMARY KEY,
    function_id uuid         NOT NULL REFERENCES fn_functions(id) ON DELETE CASCADE,
    project_id  uuid         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    org_id      uuid         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    function    varchar(40)  NOT NULL,
    runtime     varchar(12)  NOT NULL,
    status      varchar(12)  NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'building', 'succeeded', 'failed')),
    source_key  varchar(255) NOT NULL,
    image       varchar(255) NOT NULL DEFAULT '',
    error       text         NOT NULL DEFAULT '',
    log         text         NOT NULL DEFAULT '',
    attempts    int          NOT NULL DEFAULT 0,
    created_by  uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    started_at  timestamptz,
    finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_fn_builds_function ON fn_builds (function_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fn_builds_queue ON fn_builds (status, created_at) WHERE status IN ('queued', 'building');
-- at most one build of a function in flight: a second `capsule fn build` while one runs is refused (409)
CREATE UNIQUE INDEX IF NOT EXISTS uq_fn_builds_inflight ON fn_builds (function_id) WHERE status IN ('queued', 'building');
