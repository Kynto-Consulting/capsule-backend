ALTER TABLE deployments
    DROP COLUMN IF EXISTS ecs_service_arn,
    DROP COLUMN IF EXISTS ecs_task_def_arn,
    DROP COLUMN IF EXISTS app_url;
