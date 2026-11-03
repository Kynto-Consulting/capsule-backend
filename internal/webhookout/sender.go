package webhookout

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitevents"
)

const (
	attemptTimeout = 10 * time.Second
	maxRetryAfter  = 6 * time.Hour
	claimLease     = 2 * time.Minute
)

// ErrNoMailer is the delivery error of email webhooks when no mail transport is configured.
var ErrNoMailer = errors.New("email delivery is not configured on this server")

// SendTest sends the synthetic webhook.test event once, synchronously, and records it like any
// delivery (it is not retried). The returned Delivery tells the outcome.
func (s *Service) SendTest(ctx context.Context, sc Scope, id uuid.UUID) (*Delivery, error) {
	w, err := s.get(ctx, sc, id)
	if err != nil {
		return nil, err
	}
	e := gitevents.Event{
		OrgID: w.OrgID, Name: gitevents.WebhookTest, Actor: "git-capsule", CreatedAt: s.now().UTC(),
		Data: map[string]any{"message": "Prueba de webhook de Git Capsule"},
	}
	if w.ProjectID != nil {
		e.ProjectID = *w.ProjectID
		if info, perr := s.projects.ProjectInfo(ctx, *w.ProjectID); perr == nil {
			e.OrgSlug, e.ProjectSlug = info.OrgSlug, info.ProjectSlug
		}
	} else if s.orgSlug != nil {
		if slug, err := s.orgSlug(ctx, w.OrgID); err == nil {
			e.OrgSlug = slug
		}
	}
	did := uuid.New()
	body, err := BuildPayload(w.Kind, did.String(), s.baseURL, e)
	if err != nil {
		return nil, err
	}
	d := &Delivery{ID: did, WebhookID: w.ID, Event: e.Name, Payload: string(body), Status: StatusPending,
		NextAttemptAt: s.now().UTC(), CreatedAt: s.now().UTC()}
	if _, err := s.store.InsertDelivery(ctx, d); err != nil {
		return nil, err
	}
	s.attempt(ctx, d, w, true)
	return d, nil
}

// attempt performs one delivery attempt of d to w and records the outcome. final=true means no
// retry is scheduled whatever happens (test sends).
func (s *Service) attempt(ctx context.Context, d *Delivery, w *Webhook, final bool) {
	now := s.now().UTC()
	d.Attempt++
	d.RequestHeaders = nil
	d.Error, d.ResponseExcerpt, d.StatusCode, d.DurationMS = "", "", 0, 0

	if !w.Active {
		d.Status, d.Error = StatusAbandoned, "webhook is disabled"
		s.record(ctx, d)
		return
	}

	started := s.now()
	var (
		code       int
		excerpt    string
		retryAfter time.Duration
		err        error
	)
	switch w.Kind {
	case KindHTTP:
		code, excerpt, retryAfter, err = s.sendHTTP(ctx, w, d, now)
	case KindSlack, KindDiscord:
		code, excerpt, retryAfter, err = s.post(ctx, w, w.URL, []byte(d.Payload), http.Header{"Content-Type": {"application/json"}}, d)
	case KindEmail:
		err = s.sendEmail(ctx, w, d)
	default:
		err = fmt.Errorf("unknown webhook kind")
	}
	d.DurationMS = int(s.now().Sub(started) / time.Millisecond)
	d.StatusCode = code
	d.ResponseExcerpt = redact(excerpt, w)

	switch {
	case err == nil && (w.Kind == KindEmail || (code >= 200 && code < 300)):
		t := now
		d.Status, d.DeliveredAt = StatusDelivered, &t
	case code == http.StatusGone:
		d.Status = StatusAbandoned
		d.Error = "receiver answered 410 Gone: webhook disabled"
		if derr := s.store.DisableWebhook(ctx, w.ID, "receiver answered 410 Gone"); derr != nil {
			s.log.Warn("webhooks: disabling webhook after 410 failed", "webhook_id", w.ID, "error", derr)
		}
	default:
		if err != nil {
			d.Error = redact(safeErr(err), w)
		} else {
			d.Error = fmt.Sprintf("receiver answered %d", code)
		}
		if final || d.Attempt >= MaxAttempts() {
			d.Status = StatusFailed
		} else {
			wait := Backoff[d.Attempt-1]
			if retryAfter > wait {
				wait = retryAfter
			}
			d.Status = StatusPending
			d.NextAttemptAt = now.Add(wait)
		}
	}
	s.record(ctx, d)
}

func (s *Service) record(ctx context.Context, d *Delivery) {
	// The row must be written even if the request context ended while sending.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := s.store.RecordAttempt(wctx, d); err != nil {
		s.log.Warn("webhooks: recording delivery attempt failed", "delivery_id", d.ID, "error", err)
	}
}

func (s *Service) sendHTTP(ctx context.Context, w *Webhook, d *Delivery, now time.Time) (int, string, time.Duration, error) {
	ts := now.Unix()
	body := []byte(d.Payload)
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Capsule-Event", d.Event)
	h.Set("X-Capsule-Delivery", d.ID.String())
	h.Set("X-Capsule-Timestamp", strconv.FormatInt(ts, 10))
	h.Set("X-Capsule-Signature", Signature(w.Secret, ts, body))
	if w.PrevSecret != "" && w.PrevSecretExpiresAt != nil && now.Before(*w.PrevSecretExpiresAt) {
		h.Set("X-Capsule-Signature-Previous", Signature(w.PrevSecret, ts, body))
	}
	return s.post(ctx, w, w.URL, body, h, d)
}

// post sends body with the headers and reads at most 4 KiB of the answer. The URL is a secret
// for Slack/Discord, so it is never put in an error or a log line.
func (s *Service) post(ctx context.Context, w *Webhook, target string, body []byte, h http.Header, d *Delivery) (int, string, time.Duration, error) {
	cctx, cancel := context.WithTimeout(ctx, attemptTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return 0, "", 0, errors.New("invalid destination URL")
	}
	for k, vs := range h {
		req.Header[k] = vs
	}
	req.Header.Set("User-Agent", "Git-Capsule-Webhooks/1")
	d.RequestHeaders = map[string]string{}
	for k := range req.Header {
		if strings.Contains(strings.ToLower(k), "signature") {
			continue // never persist signatures
		}
		d.RequestHeaders[k] = req.Header.Get(k)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var ra time.Duration
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && secs > 0 {
			ra = time.Duration(secs) * time.Second
			if ra > maxRetryAfter {
				ra = maxRetryAfter
			}
		}
	}
	return resp.StatusCode, string(b), ra, nil
}

func (s *Service) sendEmail(ctx context.Context, w *Webhook, d *Delivery) error {
	if s.mailer == nil {
		return ErrNoMailer
	}
	var raw map[string]string
	if err := json.Unmarshal([]byte(d.Payload), &raw); err != nil {
		return errors.New("stored email payload is invalid")
	}
	d.RequestHeaders = map[string]string{"recipients": strconv.Itoa(len(w.EmailTo))}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.mailer.Send(cctx, w.EmailTo, raw["subject"], raw["text"], raw["html"]); err != nil {
		// The transport error can carry account identifiers: keep it in the server log only.
		s.log.Warn("webhooks: email transport failed", "webhook_id", w.ID, "error", err)
		return errors.New("mail transport rejected the message")
	}
	return nil
}

// safeErr renders a transport error without the request URL (net/http embeds it).
func safeErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// redact keeps an answer or error printable and short and removes anything that looks like our
// own credentials (a receiver might echo the request).
func redact(in string, w *Webhook) string {
	in = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, in)
	for _, secret := range []string{w.Secret, w.PrevSecret, w.URL} {
		if len(secret) >= 8 {
			in = strings.ReplaceAll(in, secret, "[redacted]")
		}
	}
	in = strings.Join(strings.Fields(in), " ")
	return clip(in, 512)
}

// ---- worker ------------------------------------------------------------------------------------

// ProcessDue claims the deliveries that are due and attempts them (up to 8 at a time). It returns
// how many it attempted. Safe to call from several processes: rows are claimed with a lease.
func (s *Service) ProcessDue(ctx context.Context) int {
	ds, err := s.store.ClaimDue(ctx, s.now().UTC(), claimLease, 20)
	if err != nil {
		s.log.Warn("webhooks: claiming due deliveries failed", "error", err)
		return 0
	}
	for i := range ds {
		d := ds[i]
		s.sem <- struct{}{}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			defer func() {
				if r := recover(); r != nil {
					s.log.Error("webhooks: attempt panicked", "delivery_id", d.ID, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
				}
			}()
			w, err := s.store.GetWebhook(ctx, d.WebhookID)
			if err != nil {
				if errors.Is(err, domain.ErrNotFound) {
					d.Status, d.Error = StatusAbandoned, "webhook was deleted"
					s.record(ctx, &d)
				}
				return
			}
			s.attempt(ctx, &d, w, false)
		}()
	}
	s.wg.Wait()
	return len(ds)
}

// Run delivers until ctx ends: it wakes up on new deliveries and every 5 s for retries (also
// after a restart: pending rows are in the database).
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		s.ProcessDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.pokeCh:
		}
	}
}
