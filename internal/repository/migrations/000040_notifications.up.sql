-- Git Capsule A5: bandeja de notificaciones y preferencias por usuario.
CREATE TABLE IF NOT EXISTS notifications (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users(id)         ON DELETE CASCADE,
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id uuid        REFERENCES projects(id) ON DELETE CASCADE,
    event_id   uuid        REFERENCES git_events(id) ON DELETE SET NULL,
    event      varchar(60) NOT NULL,
    title      text        NOT NULL,
    url        text        NOT NULL DEFAULT '',
    project    text        NOT NULL DEFAULT '',
    read_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
-- Un evento notifica una sola vez a cada usuario (el fan-out puede repetirse sin duplicar).
CREATE UNIQUE INDEX IF NOT EXISTS uq_notifications_user_event ON notifications(user_id, event_id) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notifications_user_time ON notifications(user_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(user_id, created_at DESC) WHERE read_at IS NULL;

CREATE TABLE IF NOT EXISTS notification_settings (
    user_id    uuid        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    channels   jsonb       NOT NULL DEFAULT '{"in_app": true, "email": false, "slack_dm": false}',
    events     jsonb       NOT NULL DEFAULT '{}',
    digest     varchar(10) NOT NULL DEFAULT 'off',
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_notification_settings_digest CHECK (digest IN ('off', 'daily', 'weekly'))
);
