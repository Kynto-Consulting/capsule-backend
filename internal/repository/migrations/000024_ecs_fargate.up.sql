ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS ecs_service_arn varchar(500),
    ADD COLUMN IF NOT EXISTS ecs_task_def_arn varchar(500),
    ADD COLUMN IF NOT EXISTS app_url varchar(500);
