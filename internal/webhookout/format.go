package webhookout

import (
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kynto/capsule/backend/internal/gitevents"
)

type idSlug struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
}

type person struct {
	Login string `json:"login"`
}

// Envelope is the signed body of kind=http webhooks (WebhookEnvelope in the OpenAPI).
type Envelope struct {
	ID         string         `json:"id"`
	Event      string         `json:"event"`
	CreatedAt  time.Time      `json:"created_at"`
	APIVersion string         `json:"api_version"`
	Org        idSlug         `json:"org"`
	Project    idSlug         `json:"project"`
	Actor      *person        `json:"actor,omitempty"`
	Data       map[string]any `json:"data"`
}

// BuildEnvelope renders the signed JSON body of event e for delivery id deliveryID.
func BuildEnvelope(deliveryID string, e gitevents.Event) ([]byte, error) {
	env := Envelope{
		ID: deliveryID, Event: e.Name, CreatedAt: e.CreatedAt.UTC(), APIVersion: APIVersion,
		Org:     idSlug{ID: e.OrgID.String(), Slug: e.OrgSlug},
		Project: idSlug{ID: e.ProjectID.String(), Slug: e.ProjectSlug},
		Data:    e.Data,
	}
	if env.Data == nil {
		env.Data = map[string]any{}
	}
	if e.Actor != "" {
		env.Actor = &person{Login: e.Actor}
	}
	return json.Marshal(env)
}

// slackEscape escapes the three characters Slack treats as control characters in mrkdwn. This
// also defuses <!channel>, <!here> and <@U123> mention injection from user-controlled text
// (PR titles, commit messages).
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s + "..."
}

// SlackPayload is the incoming-webhook message for a summary (formatted text, not the envelope).
func SlackPayload(sum gitevents.Summary) ([]byte, error) {
	var b strings.Builder
	b.WriteString("*" + slackEscape(clip(strings.Join(strings.Fields(sum.Title), " "), 250)) + "*")
	if sum.Body != "" {
		b.WriteString("\n" + slackEscape(clip(strings.TrimSpace(sum.Body), 1500)))
	}
	if sum.URL != "" {
		b.WriteString("\n<" + strings.NewReplacer("|", "%7C", ">", "%3E", "<", "%3C").Replace(sum.URL) + "|Ver en Git Capsule>")
	}
	text := b.String()
	return json.Marshal(map[string]any{
		"text":         text,
		"unfurl_links": false,
		"blocks": []any{map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": text},
		}},
	})
}

var discordColors = map[string]int{"info": 0x3b82f6, "success": 0x22c55e, "warning": 0xf59e0b, "danger": 0xef4444}

// DiscordPayload is the webhook message for a summary. allowed_mentions is empty so text from
// the repository can never ping @everyone or roles.
func DiscordPayload(sum gitevents.Summary, at time.Time) ([]byte, error) {
	embed := map[string]any{
		"title":       clip(strings.Join(strings.Fields(sum.Title), " "), 256),
		"description": clip(strings.TrimSpace(sum.Body), 2000),
		"color":       discordColors[sum.Level],
		"timestamp":   at.UTC().Format(time.RFC3339),
		"footer":      map[string]any{"text": "Git Capsule"},
	}
	if sum.URL != "" {
		embed["url"] = sum.URL
	}
	return json.Marshal(map[string]any{
		"username":         "Git Capsule",
		"allowed_mentions": map[string]any{"parse": []string{}},
		"embeds":           []any{embed},
	})
}

type emailPayload struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

// EmailPayload is the stored form of an email delivery.
func EmailPayload(sum gitevents.Summary) ([]byte, error) {
	subject, text, html := gitevents.RenderEmail(sum)
	return json.Marshal(emailPayload{Subject: subject, Text: text, HTML: html})
}

// BuildPayload renders the body stored (and later sent) for a webhook kind.
func BuildPayload(kind, deliveryID, baseURL string, e gitevents.Event) ([]byte, error) {
	switch kind {
	case KindHTTP:
		return BuildEnvelope(deliveryID, e)
	case KindSlack:
		return SlackPayload(gitevents.Describe(baseURL, e))
	case KindDiscord:
		return DiscordPayload(gitevents.Describe(baseURL, e), e.CreatedAt)
	case KindEmail:
		return EmailPayload(gitevents.Describe(baseURL, e))
	}
	return nil, &ValidationError{Field: "kind", Msg: "unknown kind"}
}
