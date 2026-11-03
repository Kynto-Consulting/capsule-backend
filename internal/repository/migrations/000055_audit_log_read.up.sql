-- Git Capsule C2: lectura de audit_logs por organizacion con cursor estable y filtros.
-- Solo columnas e indices nuevos: nada de lo existente cambia. audit_logs es de solo-anadir:
-- la aplicacion no actualiza ni borra filas (unica excepcion: la retencion, minimo 400 dias).
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS project_id uuid;
-- Quien actuo cuando no hay usuario (por ejemplo 'system' en la deriva de equipos).
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_label text NOT NULL DEFAULT '';

-- Cursor estable: (created_at, id) descendente dentro de la organizacion.
CREATE INDEX IF NOT EXISTS idx_audit_org_cursor ON audit_logs(org_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_org_project_cursor ON audit_logs(org_id, project_id, created_at DESC, id DESC) WHERE project_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_org_action_cursor ON audit_logs(org_id, action, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_org_user_cursor ON audit_logs(org_id, user_id, created_at DESC, id DESC) WHERE user_id IS NOT NULL;
-- Retencion.
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
