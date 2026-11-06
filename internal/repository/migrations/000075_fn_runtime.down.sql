ALTER TABLE fn_functions DROP CONSTRAINT IF EXISTS ck_fn_functions_runtime;
ALTER TABLE fn_functions DROP COLUMN IF EXISTS runtime;
