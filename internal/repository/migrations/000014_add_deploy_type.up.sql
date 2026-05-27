ALTER TABLE projects ADD COLUMN IF NOT EXISTS deploy_type varchar(50) NOT NULL DEFAULT 'docker';
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS deploy_type varchar(50);
