-- IPv6 rules cannot be represented in varchar(18): drop them first.
-- (The reconciler revokes the matching security-group rules on its next sweep.)
DELETE FROM database_access_rules WHERE cidr LIKE '%:%';
DELETE FROM project_port_rules    WHERE cidr LIKE '%:%';
ALTER TABLE database_access_rules ALTER COLUMN cidr TYPE varchar(18);
ALTER TABLE project_port_rules    ALTER COLUMN cidr TYPE varchar(18);
