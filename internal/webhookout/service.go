package webhookout

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

// Config builds a Service.
type Config struct {
	Store    Store
	Projects gitevents.ProjectResolver
	// OrgSlug resolves an organization slug (used by the test event of org-level webhooks); nil = "".
	OrgSlug func(ctx context.Context, orgID uuid.UUID) (string, error)
	// Policy is the anti-SSRF policy (internal/gitsource/ssrf.go). The zero value allows any
	// public host and blocks private, loopback and link-local addresses.
	Policy gitsource.Policy
	// Client sends the requests. nil = Policy.NewHTTPClient with redirects disabled. Tests inject
	// their own; production must keep the default (it re-checks the address at dial time).
	Client  *http.Client
	Mailer  gitevents.Mailer // nil: email webhooks fail with a clear error
	BaseURL string           // frontend origin for links in Slack/Discord/email
	Logger  *slog.Logger
	Now     func() time.Time // fake clock for tests
}

// Service manages outbound webhooks, subscribes to the event bus and delivers.
type Service struct {
	store    Store
	projects gitevents.ProjectResolver
	orgSlug  func(ctx context.Context, orgID uuid.UUID) (string, error)
	policy   gitsource.Policy
	client   *http.Client
	mailer   gitevents.Mailer
	baseURL  string
	log      *slog.Logger
	now      func() time.Time

	pokeCh chan struct{}
	wg     sync.WaitGroup
	sem    chan struct{}
}

// New builds the service.
func New(c Config) *Service {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	cl := c.Client
	if cl == nil {
		cl = c.Policy.NewHTTPClient(15 * time.Second)
		// A webhook receiver must answer directly: redirects are never followed (they are
		// the classic way to bounce a request towards an internal address).
		cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return &Service{
		store: c.Store, projects: c.Projects, orgSlug: c.OrgSlug, policy: c.Policy, client: cl,
		mailer: c.Mailer, baseURL: strings.TrimRight(c.BaseURL, "/"), log: c.Logger, now: c.Now,
		pokeCh: make(chan struct{}, 1), sem: make(chan struct{}, 8),
	}
}

var _ gitevents.Subscriber = (*Service)(nil)

// Name implements gitevents.Subscriber.
func (s *Service) Name() string { return "webhooks" }

func (s *Service) poke() {
	select {
	case s.pokeCh <- struct{}{}:
	default:
	}
}

// ---- input -------------------------------------------------------------------------------------

// CreateInput is WebhookInput of the API.
type CreateInput struct {
	Kind         string
	URL          string
	EmailTo      []string
	Events       []string
	Active       *bool
	BranchFilter string
}

// PatchInput carries only the fields to change.
type PatchInput struct {
	Kind         *string
	URL          *string
	EmailTo      *[]string
	Events       *[]string
	Active       *bool
	BranchFilter *string
}

var (
	branchFilterRe = regexp.MustCompile(`^[A-Za-z0-9._/*?-]{0,200}$`)
	discordHosts   = map[string]bool{"discord.com": true, "ptb.discord.com": true, "canary.discord.com": true, "discordapp.com": true}
)

func bad(field, msg string) error { return &ValidationError{Field: field, Msg: msg} }

// validateTarget checks the destination URL of kind and returns it normalized. http webhooks go
// through the anti-SSRF policy (host must resolve only to public addresses); Slack and Discord
// are pinned to their official hosts, which also keeps them out of SSRF territory.
func (s *Service) validateTarget(ctx context.Context, kind, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", bad("url", "is required")
	}
	if len(raw) > 2000 || strings.ContainsAny(raw, " \t\r\n\x00\\") {
		return "", bad("url", "is not a valid URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", bad("url", "is not a valid URL")
	}
	if u.Scheme != "https" {
		return "", bad("url", "must use https")
	}
	if u.User != nil {
		return "", bad("url", "must not contain credentials")
	}
	if u.Fragment != "" {
		return "", bad("url", "must not contain a fragment")
	}
	host := strings.ToLower(u.Hostname())
	switch kind {
	case KindSlack:
		if host != "hooks.slack.com" || !strings.HasPrefix(u.Path, "/services/") || (u.Port() != "" && u.Port() != "443") {
			return "", bad("url", "must be a Slack incoming webhook (https://hooks.slack.com/services/...)")
		}
	case KindDiscord:
		if !discordHosts[host] || !strings.HasPrefix(u.Path, "/api/webhooks/") || (u.Port() != "" && u.Port() != "443") {
			return "", bad("url", "must be a Discord webhook (https://discord.com/api/webhooks/...)")
		}
	case KindHTTP:
		if _, err := s.policy.Resolve(ctx, host); err != nil {
			if errors.Is(err, gitsource.ErrBlockedHost) {
				return "", bad("url", "points to a private or reserved address")
			}
			return "", bad("url", "host does not resolve")
		}
	}
	return u.String(), nil
}

func validateEvents(events []string) ([]string, error) {
	if len(events) == 0 {
		return nil, bad("events", "at least one event is required")
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(events))
	for _, e := range events {
		if !gitevents.Valid(e) {
			return nil, bad("events", fmt.Sprintf("unknown event %q", e))
		}
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out, nil
}

func validateEmails(list []string) ([]string, error) {
	if len(list) == 0 || len(list) > 10 {
		return nil, bad("email_to", "between 1 and 10 recipients are required")
	}
	out := make([]string, 0, len(list))
	seen := map[string]bool{}
	for _, a := range list {
		a = strings.TrimSpace(a)
		p, err := mail.ParseAddress(a)
		if err != nil || p.Address != a || strings.ContainsAny(a, "\r\n,;<>") {
			return nil, bad("email_to", fmt.Sprintf("%q is not a valid email address", a))
		}
		la := strings.ToLower(a)
		if !seen[la] {
			seen[la] = true
			out = append(out, a)
		}
	}
	return out, nil
}

func newSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "whsec_" + hex.EncodeToString(b[:]), nil
}

// ---- CRUD --------------------------------------------------------------------------------------

// Create validates and stores a webhook. For kind=http the returned Webhook carries the secret
// in clear: it is shown once and never again.
func (s *Service) Create(ctx context.Context, sc Scope, in CreateInput, createdBy uuid.UUID) (*Webhook, error) {
	w := &Webhook{
		ID: uuid.New(), OrgID: sc.OrgID, ProjectID: sc.ProjectID, Kind: in.Kind, Active: true,
		BranchFilter: strings.TrimSpace(in.BranchFilter),
	}
	if createdBy != uuid.Nil {
		w.CreatedBy = &createdBy
	}
	if in.Active != nil {
		w.Active = *in.Active
	}
	switch in.Kind {
	case KindHTTP, KindSlack, KindDiscord, KindEmail:
	default:
		return nil, bad("kind", "must be http, slack, discord or email")
	}
	var err error
	if w.Events, err = validateEvents(in.Events); err != nil {
		return nil, err
	}
	if !branchFilterRe.MatchString(w.BranchFilter) {
		return nil, bad("branch_filter", "contains characters that are not allowed in a branch pattern")
	}
	if in.Kind == KindEmail {
		if w.EmailTo, err = validateEmails(in.EmailTo); err != nil {
			return nil, err
		}
	} else {
		if w.URL, err = s.validateTarget(ctx, in.Kind, in.URL); err != nil {
			return nil, err
		}
	}
	if in.Kind == KindHTTP {
		if w.Secret, err = newSecret(); err != nil {
			return nil, err
		}
	}
	existing, err := s.store.ListWebhooks(ctx, sc)
	if err != nil {
		return nil, err
	}
	if len(existing) >= MaxWebhooksPerScope {
		return nil, bad("webhooks", fmt.Sprintf("limit of %d webhooks reached", MaxWebhooksPerScope))
	}
	if err := s.store.CreateWebhook(ctx, w); err != nil {
		return nil, err
	}
	nw, err := s.store.GetWebhook(ctx, w.ID)
	if err != nil {
		return nil, err
	}
	nw.Secret = w.Secret // in clear: the handler shows it this once
	return nw, nil
}

// get loads a webhook and checks it belongs to sc (otherwise domain.ErrNotFound: no existence leak).
func (s *Service) get(ctx context.Context, sc Scope, id uuid.UUID) (*Webhook, error) {
	w, err := s.store.GetWebhook(ctx, id)
	if err != nil {
		return nil, err
	}
	if w.OrgID != sc.OrgID || !sameProject(w.ProjectID, sc.ProjectID) {
		return nil, domain.ErrNotFound
	}
	return w, nil
}

func sameProject(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// Get returns one webhook of the scope.
func (s *Service) Get(ctx context.Context, sc Scope, id uuid.UUID) (*Webhook, error) {
	return s.get(ctx, sc, id)
}

// List returns the webhooks of the scope.
func (s *Service) List(ctx context.Context, sc Scope) ([]Webhook, error) {
	return s.store.ListWebhooks(ctx, sc)
}

// Update applies a partial change.
func (s *Service) Update(ctx context.Context, sc Scope, id uuid.UUID, in PatchInput) (*Webhook, error) {
	w, err := s.get(ctx, sc, id)
	if err != nil {
		return nil, err
	}
	if in.Kind != nil && *in.Kind != w.Kind {
		return nil, bad("kind", "cannot be changed; create a new webhook")
	}
	if in.Events != nil {
		if w.Events, err = validateEvents(*in.Events); err != nil {
			return nil, err
		}
	}
	if in.BranchFilter != nil {
		bf := strings.TrimSpace(*in.BranchFilter)
		if !branchFilterRe.MatchString(bf) {
			return nil, bad("branch_filter", "contains characters that are not allowed in a branch pattern")
		}
		w.BranchFilter = bf
	}
	if in.URL != nil {
		if w.Kind == KindEmail {
			return nil, bad("url", "email webhooks have no url")
		}
		if w.URL, err = s.validateTarget(ctx, w.Kind, *in.URL); err != nil {
			return nil, err
		}
	}
	if in.EmailTo != nil {
		if w.Kind != KindEmail {
			return nil, bad("email_to", "only email webhooks have recipients")
		}
		if w.EmailTo, err = validateEmails(*in.EmailTo); err != nil {
			return nil, err
		}
	}
	if in.Active != nil {
		w.Active = *in.Active
		if w.Active {
			w.DisabledReason = ""
		}
	}
	if err := s.store.UpdateWebhook(ctx, w); err != nil {
		return nil, err
	}
	return s.store.GetWebhook(ctx, w.ID)
}

// Delete removes a webhook (and its deliveries).
func (s *Service) Delete(ctx context.Context, sc Scope, id uuid.UUID) error {
	if _, err := s.get(ctx, sc, id); err != nil {
		return err
	}
	return s.store.DeleteWebhook(ctx, id)
}

// RotateSecret issues a new secret. The previous one keeps signing (X-Capsule-Signature-Previous)
// for RotationWindow so receivers can switch without dropping deliveries. The new secret is in
// the returned Webhook, once.
func (s *Service) RotateSecret(ctx context.Context, sc Scope, id uuid.UUID) (*Webhook, error) {
	w, err := s.get(ctx, sc, id)
	if err != nil {
		return nil, err
	}
	if w.Kind != KindHTTP {
		return nil, ErrNotRotatable
	}
	sec, err := newSecret()
	if err != nil {
		return nil, err
	}
	if err := s.store.RotateSecret(ctx, id, sec, s.now().Add(RotationWindow)); err != nil {
		return nil, err
	}
	nw, err := s.store.GetWebhook(ctx, id)
	if err != nil {
		return nil, err
	}
	nw.Secret = sec
	return nw, nil
}

// Deliveries lists the deliveries of a webhook, newest first.
func (s *Service) Deliveries(ctx context.Context, sc Scope, id uuid.UUID, cursor string, limit int) ([]Delivery, string, error) {
	if _, err := s.get(ctx, sc, id); err != nil {
		return nil, "", err
	}
	cur, err := gitevents.ParseCursor(cursor)
	if err != nil {
		return nil, "", err
	}
	if limit <= 0 {
		limit = 30
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := s.store.ListDeliveries(ctx, id, cur, limit+1)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next = gitevents.Cursor{At: last.CreatedAt, ID: last.ID}.Encode()
	}
	return rows, next, nil
}

// ErrDisabled is returned when redelivering to an inactive webhook.
var ErrDisabled = errors.New("webhook is disabled")

// Redeliver queues a new delivery with the payload of an earlier one (new delivery id, so the
// receiver sees it as a new delivery of the same event).
func (s *Service) Redeliver(ctx context.Context, sc Scope, webhookID, deliveryID uuid.UUID) (*Delivery, error) {
	w, err := s.get(ctx, sc, webhookID)
	if err != nil {
		return nil, err
	}
	old, err := s.store.GetDelivery(ctx, deliveryID)
	if err != nil {
		return nil, err
	}
	if old.WebhookID != w.ID {
		return nil, domain.ErrNotFound
	}
	if !w.Active {
		return nil, ErrDisabled
	}
	nd := &Delivery{
		ID: uuid.New(), WebhookID: w.ID, EventID: old.EventID, RedeliveryOf: &old.ID,
		Event: old.Event, Payload: old.Payload, Status: StatusPending,
		NextAttemptAt: s.now().UTC(), CreatedAt: s.now().UTC(),
	}
	if w.Kind == KindHTTP {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(old.Payload), &m); err == nil {
			idJSON, _ := json.Marshal(nd.ID.String())
			m["id"] = idJSON
			if b, err := json.Marshal(m); err == nil {
				nd.Payload = string(b)
			}
		}
	}
	if _, err := s.store.InsertDelivery(ctx, nd); err != nil {
		return nil, err
	}
	s.poke()
	return nd, nil
}

// ---- event fan-out -----------------------------------------------------------------------------

// Handle implements gitevents.Subscriber: it creates one pending delivery per matching webhook.
// It is idempotent (a delivery is unique per webhook and event).
func (s *Service) Handle(ctx context.Context, e gitevents.Event) error {
	whs, err := s.store.MatchingWebhooks(ctx, e.OrgID, e.ProjectID, e.Name)
	if err != nil {
		return err
	}
	var firstErr error
	queued := false
	for _, w := range whs {
		if !BranchMatches(w.BranchFilter, e.Branch) {
			continue
		}
		id := uuid.New()
		body, err := BuildPayload(w.Kind, id.String(), s.baseURL, e)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		d := &Delivery{ID: id, WebhookID: w.ID, Event: e.Name, Payload: string(body), Status: StatusPending,
			NextAttemptAt: s.now().UTC(), CreatedAt: s.now().UTC()}
		if e.ID != uuid.Nil {
			eid := e.ID
			d.EventID = &eid
		}
		inserted, err := s.store.InsertDelivery(ctx, d)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		queued = queued || inserted
	}
	if queued {
		s.poke()
	}
	return firstErr
}

// BranchMatches reports whether an event on branch passes a webhook branch filter. An empty
// filter passes everything, and events that are not tied to a branch always pass. The filter is
// a glob: * matches within a path segment, ** across segments, ? one character.
func BranchMatches(filter, branch string) bool {
	if filter == "" || branch == "" {
		return true
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(filter); i++ {
		switch c := filter[i]; c {
		case '*':
			if i+1 < len(filter) && filter[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(branch)
}
