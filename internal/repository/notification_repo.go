package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kynto/capsule/backend/internal/gitevents"
)

// NotificationRepository persists notifications and notification_settings (Git Capsule A5) and
// answers the recipient questions of the notifier.
type NotificationRepository struct{ pool *pgxpool.Pool }

func NewNotificationRepository(pool *pgxpool.Pool) *NotificationRepository {
	return &NotificationRepository{pool: pool}
}

var _ gitevents.NotifyStore = (*NotificationRepository)(nil)

const notificationCols = `id, user_id, org_id, project_id, event_id, event, title, url, project, (read_at IS NOT NULL), created_at`

func scanNotification(row interface{ Scan(...any) error }, n *gitevents.Notification) error {
	return row.Scan(&n.ID, &n.UserID, &n.OrgID, &n.ProjectID, &n.EventID, &n.Event, &n.Title, &n.URL, &n.Project, &n.Read, &n.CreatedAt)
}

func (r *NotificationRepository) InsertNotification(ctx context.Context, n *gitevents.Notification) (bool, error) {
	tag, err := r.pool.Exec(ctx, `
		INSERT INTO notifications (id, user_id, org_id, project_id, event_id, event, title, url, project, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT DO NOTHING`,
		n.ID, n.UserID, n.OrgID, n.ProjectID, n.EventID, n.Event, n.Title, n.URL, n.Project, n.CreatedAt)
	if err != nil {
		return false, fmt.Errorf("inserting notification: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

func (r *NotificationRepository) ListNotifications(ctx context.Context, userID uuid.UUID, unreadOnly bool, after *gitevents.Cursor, limit int) ([]gitevents.Notification, error) {
	q := `SELECT ` + notificationCols + ` FROM notifications WHERE user_id = $1`
	args := []any{userID}
	if unreadOnly {
		q += ` AND read_at IS NULL`
	}
	if after != nil {
		q += ` AND (created_at, id) < ($2, $3)`
		args = append(args, after.At, after.ID)
	}
	q += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT %d`, limit)
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing notifications: %w", err)
	}
	defer rows.Close()
	out := []gitevents.Notification{}
	for rows.Next() {
		var n gitevents.Notification
		if err := scanNotification(rows, &n); err != nil {
			return nil, fmt.Errorf("scanning notification: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (r *NotificationRepository) MarkRead(ctx context.Context, userID uuid.UUID, ids []uuid.UUID) error {
	if _, err := r.pool.Exec(ctx, `UPDATE notifications SET read_at = now() WHERE user_id = $1 AND id = ANY($2) AND read_at IS NULL`, userID, ids); err != nil {
		return fmt.Errorf("marking notifications read: %w", err)
	}
	return nil
}

func (r *NotificationRepository) MarkAllRead(ctx context.Context, userID uuid.UUID) error {
	if _, err := r.pool.Exec(ctx, `UPDATE notifications SET read_at = now() WHERE user_id = $1 AND read_at IS NULL`, userID); err != nil {
		return fmt.Errorf("marking all notifications read: %w", err)
	}
	return nil
}

// ---- settings ----------------------------------------------------------------------------------

const notificationSettingsCols = `user_id, channels, events, digest`

func scanSettings(row interface{ Scan(...any) error }, id *uuid.UUID, s *gitevents.Settings) error {
	var channels, events []byte
	var digest string
	if err := row.Scan(id, &channels, &events, &digest); err != nil {
		return err
	}
	*s = gitevents.DefaultSettings()
	s.Digest = digest
	if len(channels) > 0 {
		if err := json.Unmarshal(channels, &s.Channels); err != nil {
			return fmt.Errorf("decoding channels: %w", err)
		}
	}
	if len(events) > 0 {
		var ev map[string]([]string)
		if err := json.Unmarshal(events, &ev); err != nil {
			return fmt.Errorf("decoding events: %w", err)
		}
		if ev != nil {
			s.Events = ev
		}
	}
	return nil
}

func (r *NotificationRepository) GetSettings(ctx context.Context, userID uuid.UUID) (gitevents.Settings, error) {
	m, err := r.SettingsFor(ctx, []uuid.UUID{userID})
	if err != nil {
		return gitevents.Settings{}, err
	}
	if s, ok := m[userID]; ok {
		return s, nil
	}
	return gitevents.DefaultSettings(), nil
}

func (r *NotificationRepository) PutSettings(ctx context.Context, userID uuid.UUID, s gitevents.Settings) error {
	channels, _ := json.Marshal(s.Channels)
	events, _ := json.Marshal(s.Events)
	_, err := r.pool.Exec(ctx, `
		INSERT INTO notification_settings (user_id, channels, events, digest, updated_at)
		VALUES ($1, $2::text::jsonb, $3::text::jsonb, $4, now())
		ON CONFLICT (user_id) DO UPDATE SET channels = EXCLUDED.channels, events = EXCLUDED.events,
			digest = EXCLUDED.digest, updated_at = now()`, userID, string(channels), string(events), s.Digest)
	if err != nil {
		return fmt.Errorf("saving notification settings: %w", err)
	}
	return nil
}

func (r *NotificationRepository) SettingsFor(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]gitevents.Settings, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+notificationSettingsCols+` FROM notification_settings WHERE user_id = ANY($1)`, ids)
	if err != nil {
		return nil, fmt.Errorf("loading notification settings: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]gitevents.Settings{}
	for rows.Next() {
		var id uuid.UUID
		var s gitevents.Settings
		if err := scanSettings(rows, &id, &s); err != nil {
			return nil, fmt.Errorf("scanning notification settings: %w", err)
		}
		out[id] = s
	}
	return out, rows.Err()
}

// ---- recipients --------------------------------------------------------------------------------

func (r *NotificationRepository) ProjectAdmins(ctx context.Context, orgID, projectID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT user_id FROM project_members WHERE project_id = $2 AND role = 'admin'
		UNION
		SELECT user_id FROM org_members WHERE org_id = $1 AND role IN ('owner', 'admin')`, orgID, projectID)
	if err != nil {
		return nil, fmt.Errorf("listing project admins: %w", err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scanning project admin: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// UsersByLogin maps Forgejo logins to Capsule users through git_identities (package A2,
// migration 000034). While that table (or its forgejo_username column) does not exist the answer
// is empty rather than an error: review notifications then reach nobody, never the wrong person.
func (r *NotificationRepository) UsersByLogin(ctx context.Context, logins []string) (map[string]uuid.UUID, error) {
	lower := make([]string, 0, len(logins))
	for _, l := range logins {
		lower = append(lower, strings.ToLower(l))
	}
	rows, err := r.pool.Query(ctx, `SELECT lower(forgejo_username), user_id FROM git_identities WHERE lower(forgejo_username) = ANY($1)`, lower)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && (pe.Code == "42P01" || pe.Code == "42703") {
			return map[string]uuid.UUID{}, nil
		}
		return nil, fmt.Errorf("mapping forgejo logins: %w", err)
	}
	defer rows.Close()
	out := map[string]uuid.UUID{}
	for rows.Next() {
		var login string
		var id uuid.UUID
		if err := rows.Scan(&login, &id); err != nil {
			return nil, fmt.Errorf("scanning forgejo login: %w", err)
		}
		out[login] = id
	}
	if err := rows.Err(); err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && (pe.Code == "42P01" || pe.Code == "42703") {
			return map[string]uuid.UUID{}, nil
		}
		return nil, err
	}
	return out, nil
}

func (r *NotificationRepository) UserEmails(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, email FROM users WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, fmt.Errorf("loading user emails: %w", err)
	}
	defer rows.Close()
	out := map[uuid.UUID]string{}
	for rows.Next() {
		var id uuid.UUID
		var email string
		if err := rows.Scan(&id, &email); err != nil {
			return nil, fmt.Errorf("scanning user email: %w", err)
		}
		out[id] = email
	}
	return out, rows.Err()
}
