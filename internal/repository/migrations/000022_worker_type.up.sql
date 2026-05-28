BEGIN;
ALTER TABLE workers ADD COLUMN IF NOT EXISTS worker_type varchar(20) NOT NULL DEFAULT 'container';
ALTER TABLE workers ADD COLUMN IF NOT EXISTS queue_url varchar(500);
COMMIT;
