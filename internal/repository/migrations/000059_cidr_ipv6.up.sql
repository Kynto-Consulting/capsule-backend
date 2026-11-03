-- IPv6 support for network access rules. varchar(18) fits "255.255.255.255/32"
-- but not an IPv6 CIDR (the API stores the compressed hex form: at most
-- 39 chars + "/128" = 43). Widening a varchar is a catalog-only change and
-- re-running it is a no-op. projects.ip_allowlist is text[]: no change needed.
ALTER TABLE database_access_rules ALTER COLUMN cidr TYPE varchar(43);
ALTER TABLE project_port_rules    ALTER COLUMN cidr TYPE varchar(43);
