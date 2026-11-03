package handlers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitevents"
	"github.com/kynto/capsule/backend/internal/gitsource"
)

const maxWebhookBody = 2 << 20

// unauthorized is the one and only answer for every authentication failure
// (unknown project, no git link, bad or missing signature): no hints.
func hookUnauthorized(w http.ResponseWriter) {
	respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid signature")
}

func hookAccepted(w http.ResponseWriter, status string) {
	respondJSON(w, http.StatusAccepted, map[string]string{"status": status})
}

// InboundSink records authenticated deliveries and publishes the product events they carry
// (package A5: gitevents.Inbound). It is optional: without it the receiver behaves as before.
type InboundSink interface {
	// Accept stores the delivery once, by delivery id. duplicate=true means it was already
	// processed and must not be processed again.
	Accept(ctx context.Context, projectID uuid.UUID, ev *gitsource.Event, rawBody []byte) (duplicate bool, err error)
	// PreviousSecret is the webhook secret replaced less than 24 h ago ("" if none): after a
	// rotation, deliveries signed with it are still accepted during that window.
	PreviousSecret(ctx context.Context, projectID uuid.UUID) string
}

var (
	inboundSinkMu sync.RWMutex
	inboundSink   InboundSink
)

// SetInboundSink installs the sink (called once from the wiring).
func SetInboundSink(s InboundSink) {
	inboundSinkMu.Lock()
	inboundSink = s
	inboundSinkMu.Unlock()
}

func currentInboundSink() InboundSink {
	inboundSinkMu.RLock()
	defer inboundSinkMu.RUnlock()
	return inboundSink
}

// previewAction reports whether a pull_request action is one the preview service understands.
// Other actions (edited, review_requested) are product events only.
func previewAction(a string) bool {
	switch a {
	case "opened", "reopened", "synchronize", "closed":
		return true
	}
	return false
}

// decoySecret keeps the cost of unknown-project requests close to real ones.
const decoySecret = "capsule-decoy-secret-not-used-for-anything"

// Webhook handles POST /hooks/git/{projectID} (public, HMAC-authenticated).
func (h *GitHandler) Webhook(w http.ResponseWriter, r *http.Request) {
	projectID, err := uuid.Parse(chi.URLParam(r, "projectID"))
	body, rerr := io.ReadAll(http.MaxBytesReader(w, r.Body, maxWebhookBody))
	if err != nil || rerr != nil {
		gitsource.VerifySignature(r.Header, nil, decoySecret)
		hookUnauthorized(w)
		return
	}
	link, err := h.Git.Get(r.Context(), projectID)
	if err != nil {
		gitsource.VerifySignature(r.Header, body, decoySecret)
		if !errors.Is(err, domain.ErrNotFound) {
			h.Logger.Error("webhook: loading git link failed", "project_id", projectID, "error", err)
		}
		hookUnauthorized(w)
		return
	}
	sink := currentInboundSink()
	if !gitsource.VerifySignature(r.Header, body, link.WebhookSecret) {
		// After a secret rotation the previous secret keeps working for 24 h.
		prev := ""
		if sink != nil {
			prev = sink.PreviousSecret(r.Context(), projectID)
		}
		if prev == "" || !gitsource.VerifySignature(r.Header, body, prev) {
			hookUnauthorized(w)
			return
		}
	}

	ev, err := gitsource.ParseEvent(r.Header, body)
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_PAYLOAD", "invalid payload")
		return
	}
	if ev.Kind == gitsource.EventIgnored || !gitsource.SameRepo(link.RepoURL, ev.RepoURLs) {
		hookAccepted(w, "ignored")
		return
	}

	// Product events (A5): the delivery is recorded once (idempotency by delivery id) and published
	// to notifications and outbound webhooks, whether or not it also deploys anything.
	recorded := false
	if sink != nil {
		dup, err := sink.Accept(r.Context(), link.ProjectID, ev, body)
		switch {
		case err != nil && !errors.Is(err, gitevents.ErrNoProject):
			h.Logger.Error("webhook: recording event failed", "project_id", link.ProjectID, "event", ev.Kind, "error", err)
			respondError(w, http.StatusServiceUnavailable, "TEMPORARILY_UNAVAILABLE", "event store unavailable, retry later")
			return
		case err == nil && dup:
			hookAccepted(w, "duplicate")
			return
		case err == nil:
			recorded = true
		}
	}
	notDeploy := func() {
		if recorded {
			hookAccepted(w, "accepted")
		} else {
			hookAccepted(w, "ignored")
		}
	}

	switch ev.Kind {
	case gitsource.EventPush:
		if !link.AutoDeploy || ev.Deleted || ev.Branch != link.Branch {
			notDeploy()
			return
		}
	case gitsource.EventPullRequest:
		if !previewAction(ev.Action) || (ev.Action != "closed" && !link.PreviewEnabled) {
			notDeploy()
			return
		}
	default:
		notDeploy() // review, status, workflow_run, branch events: product events only
		return
	}
	if h.Service == nil {
		hookAccepted(w, "ignored")
		return
	}

	h.Service.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		project, err := h.Projects.GetByID(ctx, link.ProjectID)
		if err != nil {
			h.Logger.Warn("webhook: project not found", "project_id", link.ProjectID, "error", err)
			return
		}
		var herr error
		if ev.Kind == gitsource.EventPush {
			herr = h.Service.HandlePush(ctx, link, project, ev)
		} else {
			herr = h.Service.HandlePullRequest(ctx, link, project, ev)
		}
		if herr != nil {
			h.Logger.Warn("webhook: processing failed", "project_id", link.ProjectID, "event", ev.Kind, "error", herr)
		}
	})
	hookAccepted(w, "accepted")
}
