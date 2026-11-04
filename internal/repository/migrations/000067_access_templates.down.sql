DROP TRIGGER IF EXISTS role_templates_system_guard ON role_templates;
DROP TRIGGER IF EXISTS role_template_versions_immutable ON role_template_versions;
DROP TABLE IF EXISTS role_template_versions;
DROP TABLE IF EXISTS role_templates;
DROP FUNCTION IF EXISTS access_trg_template_system();
DROP FUNCTION IF EXISTS access_trg_version_immutable();
DROP FUNCTION IF EXISTS access_perms_valid(text[]);
