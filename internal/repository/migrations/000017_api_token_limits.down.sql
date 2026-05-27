BEGIN;

ALTER TABLE api_tokens
  DROP COLUMN IF EXISTS rate_limit_rpm,
  DROP COLUMN IF EXISTS ip_allowlist,
  DROP COLUMN IF EXISTS request_count,
  DROP COLUMN IF EXISTS last_count_reset;

COMMIT;
