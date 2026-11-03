package repository

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/webhookout"
)

// Every Scan must have exactly as many destinations as its column list selects, or each query
// fails at runtime ("number of field descriptions must equal number of destinations").
func TestEventWebhookNotificationScansMatchColumns(t *testing.T) {
	cases := []struct {
		name string
		cols string
		scan func(r *countingRow) error
	}{
		{"git_events", gitEventCols, func(r *countingRow) error { return scanGitEvent(r, &gitevents.Event{}) }},
		{"outbound_webhooks", webhookCols, func(r *countingRow) error { return scanWebhook(r, &webhookout.Webhook{}, &webhookEnc{}) }},
		{"webhook_deliveries", deliveryCols, func(r *countingRow) error { return scanDelivery(r, &webhookout.Delivery{}) }},
		{"notifications", notificationCols, func(r *countingRow) error { return scanNotification(r, &gitevents.Notification{}) }},
		{"notification_settings", notificationSettingsCols, func(r *countingRow) error {
			var id uuid.UUID
			return scanSettings(r, &id, &gitevents.Settings{})
		}},
	}
	for _, c := range cases {
		row := &countingRow{}
		if err := c.scan(row); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if want := len(strings.Split(c.cols, ",")); row.n != want {
			t.Errorf("%s scans %d destinations but its column list selects %d", c.name, row.n, want)
		}
	}
}
