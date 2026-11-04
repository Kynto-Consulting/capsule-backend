DROP TRIGGER IF EXISTS access_purge_environments ON environments;
DROP TRIGGER IF EXISTS access_purge_projects ON projects;
DROP TRIGGER IF EXISTS access_purge_groups ON groups;
DROP TRIGGER IF EXISTS access_purge_users ON users;
DROP TABLE IF EXISTS access_assignments;
DROP TABLE IF EXISTS group_members;
DROP TABLE IF EXISTS groups;
DROP FUNCTION IF EXISTS access_trg_purge_subject();
DROP FUNCTION IF EXISTS access_trg_assignment_check();
