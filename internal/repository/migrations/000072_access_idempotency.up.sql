-- P4 (docs/permissions/P4-NOTES.md): Idempotency-Key de las escrituras de acceso (plantillas, grupos, asignaciones).
-- La fila se escribe en la MISMA transaccion que el cambio, asi un reintento con la misma clave y el mismo cuerpo devuelve la
-- respuesta guardada y nunca duplica el efecto; la misma clave con otro cuerpo es 409 IDEMPOTENCY_CONFLICT. Solo guarda el estado
-- final de la respuesta (sin secretos). Las filas de mas de 24 h se ignoran y se reemplazan.
CREATE TABLE IF NOT EXISTS access_idempotency (
    org_id       uuid         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id      uuid         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key          varchar(128) NOT NULL,
    request_hash char(64)     NOT NULL,
    status       int          NOT NULL,
    response     jsonb,
    created_at   timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id, key)
);
CREATE INDEX IF NOT EXISTS idx_access_idempotency_created ON access_idempotency(created_at);
