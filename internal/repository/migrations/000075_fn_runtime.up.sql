-- Where a function runs: on the work node in a container (default) or as its own AWS Lambda (resumable batches).
ALTER TABLE fn_functions ADD COLUMN IF NOT EXISTS runtime varchar(12) NOT NULL DEFAULT 'container';
ALTER TABLE fn_functions DROP CONSTRAINT IF EXISTS ck_fn_functions_runtime;
ALTER TABLE fn_functions ADD CONSTRAINT ck_fn_functions_runtime CHECK (runtime IN ('container', 'lambda'));
