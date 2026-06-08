package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	bedrockruntimetypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

// isTransientBedrockError reports whether a Bedrock error is worth retrying.
// ModelErrorException ("invalid sequence as part of ToolUse"), throttling, and
// transient service errors often succeed on a second attempt — especially on
// long tool-use chains where the model occasionally emits a malformed block.
func isTransientBedrockError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, s := range []string{
		"ModelErrorException",
		"invalid sequence",
		"ThrottlingException",
		"ServiceUnavailable",
		"InternalServerException",
		"503",
		"424",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// invokeModelWithRetry calls Bedrock InvokeModel, retrying transient errors
// (up to 2 retries with short backoff).
func (h *AIHandler) invokeModelWithRetry(ctx context.Context, in *bedrockruntime.InvokeModelInput) (*bedrockruntime.InvokeModelOutput, error) {
	var out *bedrockruntime.InvokeModelOutput
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		out, err = h.aws.Bedrock.InvokeModel(ctx, in)
		if err == nil {
			return out, nil
		}
		if !isTransientBedrockError(err) {
			return nil, err
		}
		if h.logger != nil {
			h.logger.Warn("bedrock transient error, retrying", "attempt", attempt+1, "err", err.Error())
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 400 * time.Millisecond):
		}
	}
	return nil, err
}

type AIHandler struct {
	tokens   domain.APITokenRepository
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
	depsRepo domain.DeploymentRepository
	aws      *awsclient.Clients
	logger   *slog.Logger
	authSvc  domain.AuthService
	cache    domain.CacheStore // optional; used for session_id persistence
}

func NewAIHandler(
	tokens domain.APITokenRepository,
	orgs domain.OrganizationRepository,
	projects domain.ProjectRepository,
	depsRepo domain.DeploymentRepository,
	awsClients *awsclient.Clients,
	logger *slog.Logger,
	authSvc domain.AuthService,
	cache domain.CacheStore,
) *AIHandler {
	return &AIHandler{
		tokens:   tokens,
		orgs:     orgs,
		projects: projects,
		depsRepo: depsRepo,
		aws:      awsClients,
		logger:   logger,
		authSvc:  authSvc,
		cache:    cache,
	}
}

// Model catalog — static definition of available Bedrock models
func (h *AIHandler) ListModels(w http.ResponseWriter, r *http.Request) {
	type ModelCapabilities struct {
		TextGeneration  bool `json:"text_generation"`
		CodeGeneration  bool `json:"code_generation"`
		VisionAnalysis  bool `json:"vision_analysis"`
		FunctionCalling bool `json:"function_calling"`
		Streaming       bool `json:"streaming"`
	}
	type ModelPricing struct {
		InputPer1KTokens  float64 `json:"input_per_1k_tokens"`
		OutputPer1KTokens float64 `json:"output_per_1k_tokens"`
	}
	type Model struct {
		ID            string            `json:"id"`
		Name          string            `json:"name"`
		Provider      string            `json:"provider"`
		BedrockID     string            `json:"bedrock_id"`
		ContextWindow int               `json:"context_window"`
		MaxOutput     int               `json:"max_output"`
		Description   string            `json:"description"`
		Capabilities  ModelCapabilities `json:"capabilities"`
		Pricing       ModelPricing      `json:"pricing"`
		Tags          []string          `json:"tags"`
	}

	models := []Model{
		{
			ID: "nova-pro", Name: "Amazon Nova Pro", Provider: "Amazon",
			BedrockID:     "amazon.nova-pro-v1:0",
			ContextWindow: 300000, MaxOutput: 5120,
			Description:  "Amazon's most capable multimodal model. Handles complex text, images, and video with high accuracy. No approval required.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, VisionAnalysis: true, FunctionCalling: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.0008, OutputPer1KTokens: 0.0032},
			Tags:         []string{"amazon", "multimodal", "available"},
		},
		{
			ID: "nova-lite", Name: "Amazon Nova Lite", Provider: "Amazon",
			BedrockID:     "amazon.nova-lite-v1:0",
			ContextWindow: 300000, MaxOutput: 5120,
			Description:  "Fast and cost-effective multimodal model. Great for summarisation, Q&A, and light reasoning tasks.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, VisionAnalysis: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.00006, OutputPer1KTokens: 0.00024},
			Tags:         []string{"amazon", "fast", "cheap", "available"},
		},
		{
			ID: "nova-micro", Name: "Amazon Nova Micro", Provider: "Amazon",
			BedrockID:     "amazon.nova-micro-v1:0",
			ContextWindow: 128000, MaxOutput: 5120,
			Description:  "Smallest and fastest Nova model. Optimised for text tasks at ultra-low cost.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.000035, OutputPer1KTokens: 0.00014},
			Tags:         []string{"amazon", "ultra-fast", "cheapest", "available"},
		},
		{
			ID: "claude-haiku-4.5", Name: "Claude Haiku 4.5", Provider: "Anthropic",
			BedrockID:     "us.anthropic.claude-haiku-4-5-20251001-v1:0",
			ContextWindow: 200000, MaxOutput: 8192,
			Description:  "Fastest and most compact Claude model. Ideal for classification, extraction, and simple Q&A at high throughput.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, FunctionCalling: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.00025, OutputPer1KTokens: 0.00125},
			Tags:         []string{"fast", "cheap", "classification"},
		},
		{
			ID: "claude-sonnet-4.5", Name: "Claude Sonnet 4.5", Provider: "Anthropic",
			BedrockID:     "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
			ContextWindow: 200000, MaxOutput: 16000,
			Description:  "Best balance of intelligence and speed. Recommended for most production workloads including reasoning, coding, and analysis.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, VisionAnalysis: true, FunctionCalling: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.003, OutputPer1KTokens: 0.015},
			Tags:         []string{"balanced", "vision", "recommended"},
		},
		{
			ID: "claude-opus-4.5", Name: "Claude Opus 4.5", Provider: "Anthropic",
			BedrockID:     "us.anthropic.claude-opus-4-5-20251101-v1:0",
			ContextWindow: 200000, MaxOutput: 32000,
			Description:  "Most powerful Claude model. Best for complex reasoning, research synthesis, and tasks requiring deep analysis.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, VisionAnalysis: true, FunctionCalling: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.015, OutputPer1KTokens: 0.075},
			Tags:         []string{"powerful", "complex-reasoning", "research"},
		},
		{
			ID: "llama3-3-70b", Name: "Meta Llama 3.3 70B Instruct", Provider: "Meta",
			BedrockID:     "us.meta.llama3-3-70b-instruct-v1:0",
			ContextWindow: 128000, MaxOutput: 8192,
			Description:  "Meta's latest open model. Strong instruction-following, coding assistance, and multilingual support.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.00099, OutputPer1KTokens: 0.00099},
			Tags:         []string{"open-source", "multilingual"},
		},
		{
			ID: "llama3-2-90b", Name: "Meta Llama 3.2 90B Instruct", Provider: "Meta",
			BedrockID:     "us.meta.llama3-2-90b-instruct-v1:0",
			ContextWindow: 128000, MaxOutput: 8192,
			Description:  "Large vision-capable Llama model for complex reasoning and image understanding tasks.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, VisionAnalysis: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.00072, OutputPer1KTokens: 0.00072},
			Tags:         []string{"open-source", "vision"},
		},
		{
			ID: "deepseek-r1", Name: "DeepSeek-R1", Provider: "DeepSeek",
			BedrockID:     "us.deepseek.r1-v1:0",
			ContextWindow: 64000, MaxOutput: 8192,
			Description:  "Advanced reasoning model with extended chain-of-thought. Excellent for math, logic, and complex problem solving.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.00135, OutputPer1KTokens: 0.0054},
			Tags:         []string{"reasoning", "math", "chain-of-thought"},
		},
	}

	respondJSON(w, http.StatusOK, map[string]any{"data": models})
}

// SkillDoc serves a markdown integration guide for the AI API.
// Public — GET /ai/skill.md (and /ai/skill). text/markdown.
func (h *AIHandler) SkillDoc(w http.ResponseWriter, r *http.Request) {
	const doc = `# Tumi AI — OpenAI-compatible Gateway

Base URL: ` + "`https://api.tumi-ai.com/api/v1/ai`" + `

A single, OpenAI-compatible endpoint over Amazon Bedrock (Nova, Claude, Llama,
DeepSeek). Drop-in with any OpenAI SDK — just change ` + "`base_url`" + ` and ` + "`api_key`" + `.

## Authentication

Send a platform key as a bearer token:

` + "```" + `
Authorization: Bearer csk_live_xxx     # AI proxy key (for /ai/* only)
Authorization: Bearer cap_xxx          # full platform API key
Authorization: Bearer <jwt>            # session token
` + "```" + `

Create an AI key: ` + "`POST /api/v1/ai/keys`" + ` (body: ` + "`{\"name\":\"my-key\"}`" + `).

## Chat completions

` + "```python" + `
from openai import OpenAI
client = OpenAI(
    api_key="csk_live_xxx",
    base_url="https://api.tumi-ai.com/api/v1/ai",
)
resp = client.chat.completions.create(
    model="nova-lite",
    messages=[{"role": "user", "content": "Hello!"}],
)
print(resp.choices[0].message.content)
` + "```" + `

Endpoints:
- ` + "`POST /ai/chat/completions`" + ` — OpenAI SDK path
- ` + "`POST /ai/chat`" + ` — same handler, short path

## Streaming

Set ` + "`stream: true`" + ` for real Server-Sent Events (token-by-token).
The final chunk carries ` + "`usage`" + ` ` + "`{prompt_tokens, completion_tokens, total_tokens}`" + `.
On a mid-stream model error the final chunk has ` + "`finish_reason: \"error\"`" + ` plus a
` + "`{\"error\": {\"code\": \"AI_MODEL_ERROR\"}}`" + ` event — finalize or retry on that.

## Multimodal (images)

Send ` + "`content`" + ` as an array of parts. Data-URL base64 images are converted to
the Bedrock image format automatically:

` + "```json" + `
{"role": "user", "content": [
  {"type": "text", "text": "What is in this image?"},
  {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBOR..."}}
]}
` + "```" + `

## Tools / function calling

Pass OpenAI-format ` + "`tools`" + ` and ` + "`tool_choice`" + `. Responses use ` + "`tool_calls`" + ` with
` + "`finish_reason: \"tool_calls\"`" + `. Send results back as ` + "`role: \"tool\"`" + ` messages
(` + "`tool_call_id`" + ` + ` + "`content`" + `).

## Prompt caching (automatic)

The gateway is stateless — you re-send history each request. When your **system
prompt** is large (≥ ~1024 tokens) the gateway automatically attaches a Bedrock
cache point to it. Within the 5-minute TTL, repeated identical system prompts
are billed at a fraction of the cost and respond faster.

Rules to keep the cache warm:
1. Keep the system prompt **byte-identical** across turns. Put anything dynamic
   (date, user id, time) in ` + "`messages`" + `, never in the system prompt.
2. Caching only activates above the minimum size — short system prompts are
   sent uncached (no penalty).
3. Multi-device continuity: store history in your own DB keyed by chat id and
   re-send it; the cache point keeps cost/latency low despite re-sending.

## Models

Full catalog: ` + "`GET /api/v1/ai/models`" + `

| id | provider | notes |
|----|----------|-------|
| nova-micro | Amazon | cheapest, text-only |
| nova-lite | Amazon | fast, multimodal |
| nova-pro | Amazon | capable, multimodal |
| claude-haiku-4.5 | Anthropic | fast, tools |
| claude-sonnet-4.5 | Anthropic | balanced, vision |
| claude-opus-4.5 | Anthropic | most powerful |
| llama3-3-70b | Meta | open, multilingual |
| llama3-2-90b | Meta | open, vision |
| deepseek-r1 | DeepSeek | reasoning / CoT |

Unknown model ids fall back to ` + "`nova-lite`" + `.

## Extensions (non-OpenAI fields)

These optional fields on the request body add gateway-managed behaviour:

- ` + "`session_id`" + ` (alias ` + "`agent_id`" + `): Capsule-managed history. With a session
  id the gateway stores the conversation in its own Redis (TTL **24h**) and you
  send only the **new** turn each request — it loads prior turns, calls the
  model, and persists the reply. Multi-device continuity. This is **Capsule's
  own store, not AWS Bedrock Sessions/Agents** — your data stays in Capsule.
  Omit it to stay fully stateless (you send full history).
- ` + "`system`" + `: system-prompt override. Wins over any ` + "`role:system`" + ` message.
  Your model's own ` + "`<think>`" + `/reasoning output is never stripped — it's yours.
- ` + "`disable_tools`" + `: ignore ` + "`tools[]`" + ` and force no tool use this turn.

` + "```json" + `
{
  "model": "nova-pro",
  "session_id": "chat-user123-456",
  "system": "You are a pure text router.",
  "disable_tools": true,
  "messages": [{"role": "user", "content": "hi"}]
}
` + "```" + `

## Notes

- Stateless by default: no conversation id unless you pass ` + "`session_id`" + `.
- Transient Bedrock errors (424 ModelErrorException, throttling) are retried
  automatically up to 2x before surfacing.
`

	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(doc))
}

// UpdateKey updates rate limit and IP allowlist for an API key
func (h *AIHandler) UpdateKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing authenticated user")
		return
	}

	keyID, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid key id")
		return
	}

	var req struct {
		RateLimitRPM int    `json:"rate_limit_rpm"`
		IPAllowlist  string `json:"ip_allowlist"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	updated, err := h.tokens.Update(r.Context(), keyID, req.RateLimitRPM, req.IPAllowlist)
	if err == domain.ErrNotFound {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "key not found")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update key")
		return
	}

	respondJSON(w, http.StatusOK, updated)
}

// Keys management
func (h *AIHandler) CreateKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing authenticated user")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.Name == "" {
		req.Name = "Default Key"
	}

	plainKey := fmt.Sprintf("csk_live_%s", randomString(24))
	hashed := hashToken(plainKey)

	token, err := h.tokens.Create(r.Context(), &domain.APIToken{
		UserID:    user.ID,
		Name:      req.Name,
		TokenHash: hashed,
		Prefix:    "csk_live_",
		Scopes:    "*",
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create api key: "+err.Error())
		return
	}

	type createKeyResponse struct {
		ID        uuid.UUID  `json:"id"`
		Name      string     `json:"name"`
		Key       string     `json:"key"`
		Prefix    string     `json:"prefix"`
		CreatedAt time.Time  `json:"created_at"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}

	respondJSON(w, http.StatusCreated, createKeyResponse{
		ID:        token.ID,
		Name:      token.Name,
		Key:       plainKey,
		Prefix:    token.Prefix,
		CreatedAt: token.CreatedAt,
		ExpiresAt: token.ExpiresAt,
	})
}

func (h *AIHandler) ListKeys(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing authenticated user")
		return
	}

	keys, err := h.tokens.ListByUser(r.Context(), user.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list api keys")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"data": keys})
}

func (h *AIHandler) RevokeKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing authenticated user")
		return
	}

	keyID, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid key id")
		return
	}

	if err := h.tokens.Revoke(r.Context(), keyID); err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to revoke key")
		return
	}

	respondNoContent(w)
}

// OpenAI compatible Chat endpoint
func (h *AIHandler) Chat(w http.ResponseWriter, r *http.Request) {
	var user *domain.User

	// Support direct token authentication or standard JWT session auth
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer csk_live_") {
		plainToken := strings.TrimPrefix(authHeader, "Bearer ")
		hashed := hashToken(plainToken)

		tokenRecord, err := h.tokens.GetByHash(r.Context(), hashed)
		if err != nil {
			respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid API token")
			return
		}

		// Enforce IP allowlist
		if tokenRecord.IPAllowlist != "" {
			clientIP := r.Header.Get("X-Forwarded-For")
			if clientIP == "" {
				clientIP = r.RemoteAddr
			}
			if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
				clientIP = clientIP[:idx]
			}
			clientIP = strings.TrimSpace(strings.Split(clientIP, ",")[0])
			allowed := false
			for _, ip := range strings.Split(tokenRecord.IPAllowlist, ",") {
				if strings.TrimSpace(ip) == clientIP {
					allowed = true
					break
				}
			}
			if !allowed {
				respondError(w, http.StatusForbidden, "IP_BLOCKED", "request IP not in allowlist")
				return
			}
		}

		// Enforce rate limit (simple count-based, resets every minute)
		if tokenRecord.RateLimitRPM > 0 && tokenRecord.RequestCount >= int64(tokenRecord.RateLimitRPM) {
			respondError(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", fmt.Sprintf("rate limit of %d RPM exceeded", tokenRecord.RateLimitRPM))
			return
		}

		_ = h.tokens.IncrementUsage(r.Context(), tokenRecord.ID)

		user = &domain.User{ID: tokenRecord.UserID}
	} else {
		// Try session-based auth (JWT) — route is outside auth middleware, so validate manually
		user = middleware.GetUser(r.Context())
		if user == nil && h.authSvc != nil {
			rawToken := strings.TrimPrefix(authHeader, "Bearer ")
			if rawToken != "" {
				if validated, err := h.authSvc.ValidateAccessToken(r.Context(), rawToken); err == nil {
					user = validated
				}
			}
		}
	}

	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing credentials")
		return
	}

	// --- OpenAI-compatible request parsing ---
	type rawMessage struct {
		Role       string          `json:"role"`
		Content    json.RawMessage `json:"content"`
		ToolCallID string          `json:"tool_call_id"` // role:tool
		ToolCalls  []struct {
			ID       string `json:"id"`
			Type     string `json:"type"`
			Function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"` // role:assistant
	}
	var rawReq struct {
		Model    string       `json:"model"`
		Messages []rawMessage `json:"messages"`
		Stream   bool         `json:"stream"`
		Tools    []struct {
			Type     string `json:"type"`
			Function struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				Parameters  json.RawMessage `json:"parameters"`
			} `json:"function"`
		} `json:"tools"`
		ToolChoice json.RawMessage `json:"tool_choice"`

		// Extensions (non-OpenAI):
		SessionID    string `json:"session_id"`    // server-side history persistence (multi-device)
		AgentID      string `json:"agent_id"`      // alias for session_id
		System       string `json:"system"`        // system prompt override (wins over system-role msgs)
		DisableTools bool   `json:"disable_tools"` // ignore tools[] + force no tool use
	}
	if err := json.NewDecoder(r.Body).Decode(&rawReq); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	// Resolve aliases
	sessionID := rawReq.SessionID
	if sessionID == "" {
		sessionID = rawReq.AgentID
	}

	// --- Session history (agent_id / session_id) ---
	// When a session id is provided and a cache is available, the gateway owns
	// the history: it loads prior turns, the client need only send the new
	// turn(s). This gives Bedrock-Agents-style multi-device continuity while
	// keeping our own store as the source of truth.
	const sessionTTL = 24 * 3600 // 24h
	sessionKey := ""
	var priorMessages []rawMessage
	if sessionID != "" && h.cache != nil {
		sessionKey = "ai:session:" + sessionID
		if stored, err := h.cache.Get(r.Context(), sessionKey); err == nil && stored != "" {
			_ = json.Unmarshal([]byte(stored), &priorMessages)
		}
	}
	// Effective conversation = prior history + this request's messages
	rawReq.Messages = append(priorMessages, rawReq.Messages...)

	if len(rawReq.Messages) == 0 {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "messages cannot be empty")
		return
	}

	// disable_tools: drop tools and force no tool use
	if rawReq.DisableTools {
		rawReq.Tools = nil
		rawReq.ToolChoice = json.RawMessage(`"none"`)
	}

	// saveSession persists the full conversation (effective history + the new
	// assistant reply) under the session key, refreshing the TTL. No-op when no
	// session id was provided or no cache is configured.
	saveSession := func(assistantText string) {
		if sessionKey == "" || h.cache == nil || assistantText == "" {
			return
		}
		type storeMsg struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		}
		hist := make([]storeMsg, 0, len(rawReq.Messages)+1)
		for _, m := range rawReq.Messages {
			hist = append(hist, storeMsg{Role: m.Role, Content: m.Content})
		}
		assistantJSON, _ := json.Marshal(assistantText)
		hist = append(hist, storeMsg{Role: "assistant", Content: assistantJSON})
		if b, err := json.Marshal(hist); err == nil {
			_ = h.cache.Set(r.Context(), sessionKey, string(b), sessionTTL)
		}
	}

	// contentPart — normalized internal representation of one content item
	type contentPart struct {
		IsImage   bool
		Text      string
		Format    string // jpeg, png, gif, webp
		B64Data   string // raw base64 (no data-URL prefix)
		MediaType string // image/jpeg etc
	}

	// parseContent converts OpenAI content (string | array | null) → []contentPart
	parseContent := func(raw json.RawMessage) []contentPart {
		if len(raw) == 0 || string(raw) == "null" {
			return nil // assistant tool_call messages have content:null
		}
		var text string
		if err := json.Unmarshal(raw, &text); err == nil {
			return []contentPart{{Text: text}}
		}
		var parts []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			ImageURL *struct {
				URL string `json:"url"`
			} `json:"image_url"`
		}
		if err := json.Unmarshal(raw, &parts); err != nil {
			return nil
		}
		var out []contentPart
		for _, p := range parts {
			switch p.Type {
			case "text":
				out = append(out, contentPart{Text: p.Text})
			case "image_url":
				if p.ImageURL == nil {
					continue
				}
				url := p.ImageURL.URL
				if strings.HasPrefix(url, "data:") {
					// data:image/jpeg;base64,<b64>
					halves := strings.SplitN(url, ",", 2)
					if len(halves) == 2 {
						meta := strings.TrimPrefix(halves[0], "data:")
						mediaType := strings.Split(meta, ";")[0]
						format := strings.TrimPrefix(mediaType, "image/")
						out = append(out, contentPart{
							IsImage: true, Format: format,
							B64Data: halves[1], MediaType: mediaType,
						})
					}
				} else {
					// Plain URL — pass as text reference (Bedrock needs bytes)
					out = append(out, contentPart{Text: "[image: " + url + "]"})
				}
			}
		}
		return out
	}

	// Map model IDs — Nova models available without use-case form; Claude requires Anthropic approval
	type modelDef struct {
		bedrockID string
		isNova    bool
	}
	modelMap := map[string]modelDef{
		"nova-pro":          {"amazon.nova-pro-v1:0", true},
		"nova-lite":         {"amazon.nova-lite-v1:0", true},
		"nova-micro":        {"amazon.nova-micro-v1:0", true},
		"claude-haiku-4.5":  {"us.anthropic.claude-haiku-4-5-20251001-v1:0", false},
		"claude-sonnet-4.5": {"us.anthropic.claude-sonnet-4-5-20250929-v1:0", false},
		"claude-opus-4.5":   {"us.anthropic.claude-opus-4-5-20251101-v1:0", false},
		"llama3-3-70b":      {"us.meta.llama3-3-70b-instruct-v1:0", false},
		"llama3-2-90b":      {"us.meta.llama3-2-90b-instruct-v1:0", false},
		"deepseek-r1":       {"us.deepseek.r1-v1:0", false},
	}
	selected, ok := modelMap[rawReq.Model]
	if !ok {
		selected = modelDef{"amazon.nova-lite-v1:0", true}
	}
	awsModelID := selected.bedrockID

	// Build Bedrock payload — Nova and Anthropic have different schemas
	type bedrockMsg struct {
		Role    string           `json:"role"`
		Content []map[string]any `json:"content"`
	}

	var systemPrompt string
	var bedrockMessages []bedrockMsg // Anthropic format
	var novaMessages []bedrockMsg    // Nova format

	for _, m := range rawReq.Messages {
		switch m.Role {
		case "system":
			parts := parseContent(m.Content)
			for _, p := range parts {
				if !p.IsImage {
					systemPrompt += p.Text
				}
			}
			continue

		case "tool":
			// OpenAI tool result → Nova toolResult inside a user turn
			var resultText string
			if err := json.Unmarshal(m.Content, &resultText); err != nil {
				resultText = string(m.Content)
			}
			novaMessages = append(novaMessages, bedrockMsg{
				Role: "user",
				Content: []map[string]any{{
					"toolResult": map[string]any{
						"toolUseId": m.ToolCallID,
						"content":   []map[string]any{{"text": resultText}},
						"status":    "success",
					},
				}},
			})
			bedrockMessages = append(bedrockMessages, bedrockMsg{
				Role: "user",
				Content: []map[string]any{{
					"type":        "tool_result",
					"tool_use_id": m.ToolCallID,
					"content":     resultText,
				}},
			})
			continue

		case "assistant":
			if len(m.ToolCalls) > 0 {
				// Assistant requested tool calls
				var novaContent []map[string]any
				var anthropicContent []map[string]any
				for _, tc := range m.ToolCalls {
					var args map[string]any
					_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
					novaContent = append(novaContent, map[string]any{
						"toolUse": map[string]any{
							"toolUseId": tc.ID,
							"name":      tc.Function.Name,
							"input":     args,
						},
					})
					anthropicContent = append(anthropicContent, map[string]any{
						"type":  "tool_use",
						"id":    tc.ID,
						"name":  tc.Function.Name,
						"input": args,
					})
				}
				novaMessages = append(novaMessages, bedrockMsg{Role: "assistant", Content: novaContent})
				bedrockMessages = append(bedrockMessages, bedrockMsg{Role: "assistant", Content: anthropicContent})
				continue
			}
			fallthrough

		default:
			parts := parseContent(m.Content)
			var novaContent []map[string]any
			var anthropicContent []map[string]any
			for _, p := range parts {
				if p.IsImage {
					novaContent = append(novaContent, map[string]any{
						"image": map[string]any{
							"format": p.Format,
							"source": map[string]any{"bytes": p.B64Data},
						},
					})
					anthropicContent = append(anthropicContent, map[string]any{
						"type": "image",
						"source": map[string]any{
							"type":       "base64",
							"media_type": p.MediaType,
							"data":       p.B64Data,
						},
					})
				} else {
					novaContent = append(novaContent, map[string]any{"text": p.Text})
					anthropicContent = append(anthropicContent, map[string]any{"type": "text", "text": p.Text})
				}
			}
			novaMessages = append(novaMessages, bedrockMsg{Role: m.Role, Content: novaContent})
			bedrockMessages = append(bedrockMessages, bedrockMsg{Role: m.Role, Content: anthropicContent})
		}
	}

	// System prompt override — explicit `system` field wins over system-role
	// messages (so callers can pin behaviour regardless of conversation history).
	// The model's own <think>/<thinking> output is left untouched — that's the
	// caller's CoT, not ours to strip.
	if rawReq.System != "" {
		systemPrompt = rawReq.System
	}

	// Prompt caching activates only above Bedrock's minimum cacheable block
	// size (~1024 tokens ≈ 4000 chars). Below that, adding a cache point is
	// ignored, so we only attach one when the system prompt is large enough.
	// This caches the (typically static) system prompt across requests within
	// the 5-minute TTL → up to ~90% cheaper input tokens + lower latency when
	// the client re-sends history each turn.
	const cacheMinChars = 4000
	cacheSystem := systemPrompt != "" && len(systemPrompt) >= cacheMinChars

	// History prefix caching: cache everything up to (but not including) the
	// latest turn. The prefix [all messages except the last] is stable turn to
	// turn, so each new turn only pays to process the new message — the prior
	// conversation is read from Bedrock's cache. Big win when re-sending history
	// (incl. multi-device: cache is server-side in Bedrock, keyed by content,
	// not by caller/device). Gated to real conversations so the min-size rule
	// isn't wasted; Bedrock silently ignores cache points below the threshold.
	cacheHistory := len(novaMessages) >= 3
	if cacheHistory {
		k := len(novaMessages) - 2 // second-to-last built message
		if k >= 0 {
			// Nova: append a cachePoint content block to that message
			novaMessages[k].Content = append(novaMessages[k].Content,
				map[string]any{"cachePoint": map[string]any{"type": "default"}})
		}
		ka := len(bedrockMessages) - 2
		if ka >= 0 && len(bedrockMessages[ka].Content) > 0 {
			// Anthropic: cache_control on that message's last content block
			last := len(bedrockMessages[ka].Content) - 1
			bedrockMessages[ka].Content[last]["cache_control"] = map[string]any{"type": "ephemeral"}
		}
	}

	// Build Bedrock payload
	var payloadBytes []byte
	if selected.isNova {
		novaPayload := map[string]any{
			"messages":        novaMessages,
			"inferenceConfig": map[string]any{"maxTokens": 4096},
		}
		if systemPrompt != "" {
			sys := []map[string]any{{"text": systemPrompt}}
			if cacheSystem {
				// Nova: cachePoint after the system text caches everything before it
				sys = append(sys, map[string]any{"cachePoint": map[string]any{"type": "default"}})
			}
			novaPayload["system"] = sys
		}
		// Convert OpenAI tools → Nova toolConfig
		if len(rawReq.Tools) > 0 {
			var novaTools []map[string]any
			for _, t := range rawReq.Tools {
				var params any
				_ = json.Unmarshal(t.Function.Parameters, &params)
				novaTools = append(novaTools, map[string]any{
					"toolSpec": map[string]any{
						"name":        t.Function.Name,
						"description": t.Function.Description,
						"inputSchema": map[string]any{"json": params},
					},
				})
			}
			toolChoice := map[string]any{"auto": map[string]any{}}
			if len(rawReq.ToolChoice) > 0 {
				var tc string
				if json.Unmarshal(rawReq.ToolChoice, &tc) == nil && tc == "none" {
					toolChoice = map[string]any{"any": map[string]any{}}
				}
			}
			novaPayload["toolConfig"] = map[string]any{"tools": novaTools, "toolChoice": toolChoice}
		}
		payloadBytes, _ = json.Marshal(novaPayload)
	} else {
		anthropicPayload := map[string]any{
			"anthropic_version": "bedrock-2023-05-31",
			"max_tokens":        4096,
			"messages":          bedrockMessages,
		}
		if systemPrompt != "" {
			if cacheSystem {
				// Anthropic: system as a content block with cache_control:ephemeral
				anthropicPayload["system"] = []map[string]any{{
					"type":          "text",
					"text":          systemPrompt,
					"cache_control": map[string]any{"type": "ephemeral"},
				}}
			} else {
				anthropicPayload["system"] = systemPrompt
			}
		}
		if len(rawReq.Tools) > 0 {
			var claudeTools []map[string]any
			for _, t := range rawReq.Tools {
				var params any
				_ = json.Unmarshal(t.Function.Parameters, &params)
				claudeTools = append(claudeTools, map[string]any{
					"name":         t.Function.Name,
					"description":  t.Function.Description,
					"input_schema": params,
				})
			}
			anthropicPayload["tools"] = claudeTools
		}
		payloadBytes, _ = json.Marshal(anthropicPayload)
	}

	if h.aws == nil {
		respondError(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI features require AWS Bedrock configuration")
		return
	}

	chatID := "chatcmpl-" + randomString(12)
	created := time.Now().Unix()

	// ── SSE real streaming ────────────────────────────────────────────────────
	if rawReq.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		flusher, canFlush := w.(http.Flusher)

		sendSSE := func(data any) {
			b, _ := json.Marshal(data)
			fmt.Fprintf(w, "data: %s\n\n", b)
			if canFlush {
				flusher.Flush()
			}
		}
		makeChunk := func(delta map[string]any, finishReason *string, usage map[string]any) map[string]any {
			choice := map[string]any{"index": 0, "delta": delta, "finish_reason": finishReason}
			chunk := map[string]any{
				"id": chatID, "object": "chat.completion.chunk",
				"created": created, "model": rawReq.Model,
				"choices": []any{choice},
			}
			if usage != nil {
				chunk["usage"] = usage
			}
			return chunk
		}

		// Open stream, retrying transient errors before any bytes are written.
		var streamOut *bedrockruntime.InvokeModelWithResponseStreamOutput
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			streamOut, err = h.aws.Bedrock.InvokeModelWithResponseStream(r.Context(), &bedrockruntime.InvokeModelWithResponseStreamInput{
				ModelId:     aws.String(awsModelID),
				ContentType: aws.String("application/json"),
				Accept:      aws.String("application/json"),
				Body:        payloadBytes,
			})
			if err == nil || !isTransientBedrockError(err) {
				break
			}
			h.logger.Warn("bedrock stream transient error, retrying", "attempt", attempt+1, "err", err.Error())
			select {
			case <-r.Context().Done():
				err = r.Context().Err()
			case <-time.After(time.Duration(attempt+1) * 400 * time.Millisecond):
			}
		}
		if err != nil {
			sendSSE(map[string]any{"error": map[string]any{"code": "AI_ERROR", "message": err.Error()}})
			fmt.Fprintf(w, "data: [DONE]\n\n")
			if canFlush {
				flusher.Flush()
			}
			return
		}
		defer streamOut.GetStream().Close()

		// Send initial role delta
		sendSSE(makeChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil))

		finishReason := "stop"
		var inputTokens, outputTokens int
		var cacheReadTokens, cacheWriteTokens int
		var fullText strings.Builder // accumulated assistant text for session persistence

		// Tool call accumulation per content block index
		type tcBlock struct {
			idx  int
			id   string
			name string
		}
		tcBlocks := map[int]*tcBlock{}
		var tcCounter int

		for event := range streamOut.GetStream().Events() {
			chunk, ok := event.(*bedrockruntimetypes.ResponseStreamMemberChunk)
			if !ok {
				continue
			}
			b := chunk.Value.Bytes

			// Nova stream event shape
			var evt struct {
				ContentBlockDelta *struct {
					ContentBlockIndex int `json:"contentBlockIndex"`
					Delta             struct {
						Text    string `json:"text"`
						ToolUse *struct {
							Input string `json:"input"`
						} `json:"toolUse"`
					} `json:"delta"`
				} `json:"contentBlockDelta"`
				ContentBlockStart *struct {
					ContentBlockIndex int `json:"contentBlockIndex"`
					Start             struct {
						ToolUse *struct {
							ToolUseID string `json:"toolUseId"`
							Name      string `json:"name"`
						} `json:"toolUse"`
					} `json:"start"`
				} `json:"contentBlockStart"`
				MessageStop *struct {
					StopReason string `json:"stopReason"`
				} `json:"messageStop"`
				Metadata *struct {
					Usage struct {
						InputTokens           int `json:"inputTokens"`
						OutputTokens          int `json:"outputTokens"`
						CacheReadInputTokens  int `json:"cacheReadInputTokenCount"`
						CacheWriteInputTokens int `json:"cacheWriteInputTokenCount"`
					} `json:"usage"`
				} `json:"metadata"`
				// Anthropic streaming
				Type  string `json:"type"`
				Index int    `json:"index"`
				Delta *struct {
					Type       string `json:"type"`
					Text       string `json:"text"`
					StopReason string `json:"stop_reason"`
				} `json:"delta"`
				Usage *struct {
					InputTokens              int `json:"input_tokens"`
					OutputTokens             int `json:"output_tokens"`
					CacheReadInputTokens     int `json:"cache_read_input_tokens"`
					CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
				} `json:"usage"`
			}
			if err := json.Unmarshal(b, &evt); err != nil {
				continue
			}

			// ── Nova events ──────────────────────────────────────────────────
			if evt.ContentBlockStart != nil && evt.ContentBlockStart.Start.ToolUse != nil {
				tu := evt.ContentBlockStart.Start.ToolUse
				idx := evt.ContentBlockStart.ContentBlockIndex
				tc := &tcBlock{idx: tcCounter, id: tu.ToolUseID, name: tu.Name}
				tcBlocks[idx] = tc
				tcCounter++
				sendSSE(makeChunk(map[string]any{
					"tool_calls": []map[string]any{{
						"index": tc.idx, "id": tu.ToolUseID, "type": "function",
						"function": map[string]any{"name": tu.Name, "arguments": ""},
					}},
				}, nil, nil))
			}
			if evt.ContentBlockDelta != nil {
				d := evt.ContentBlockDelta.Delta
				if d.Text != "" {
					fullText.WriteString(d.Text)
					sendSSE(makeChunk(map[string]any{"content": d.Text}, nil, nil))
				}
				if d.ToolUse != nil && d.ToolUse.Input != "" {
					if tc, ok := tcBlocks[evt.ContentBlockDelta.ContentBlockIndex]; ok {
						sendSSE(makeChunk(map[string]any{
							"tool_calls": []map[string]any{{
								"index":    tc.idx,
								"function": map[string]any{"arguments": d.ToolUse.Input},
							}},
						}, nil, nil))
					}
				}
			}
			if evt.MessageStop != nil {
				if evt.MessageStop.StopReason == "tool_use" {
					finishReason = "tool_calls"
				}
			}
			if evt.Metadata != nil {
				inputTokens = evt.Metadata.Usage.InputTokens
				outputTokens = evt.Metadata.Usage.OutputTokens
				cacheReadTokens = evt.Metadata.Usage.CacheReadInputTokens
				cacheWriteTokens = evt.Metadata.Usage.CacheWriteInputTokens
			}

			// ── Anthropic events ─────────────────────────────────────────────
			if evt.Type == "content_block_delta" && evt.Delta != nil && evt.Delta.Text != "" {
				fullText.WriteString(evt.Delta.Text)
				sendSSE(makeChunk(map[string]any{"content": evt.Delta.Text}, nil, nil))
			}
			if evt.Type == "message_delta" && evt.Delta != nil && evt.Delta.StopReason == "tool_use" {
				finishReason = "tool_calls"
			}
			if evt.Type == "message_start" && evt.Usage != nil {
				inputTokens = evt.Usage.InputTokens
				if evt.Usage.CacheReadInputTokens > 0 {
					cacheReadTokens = evt.Usage.CacheReadInputTokens
				}
				if evt.Usage.CacheCreationInputTokens > 0 {
					cacheWriteTokens = evt.Usage.CacheCreationInputTokens
				}
			}
			if evt.Type == "message_delta" && evt.Usage != nil {
				outputTokens = evt.Usage.OutputTokens
			}
		}
		streamErr := streamOut.GetStream().Err()
		if streamErr != nil {
			// Mid-stream Bedrock error (e.g. 424 ModelErrorException "invalid
			// sequence as part of ToolUse"). Surface it explicitly so the client
			// can finalize/retry instead of treating an empty turn as success.
			h.logger.Error("bedrock stream error", "err", streamErr)
			finishReason = "error"
			sendSSE(map[string]any{"error": map[string]any{
				"code":    "AI_MODEL_ERROR",
				"message": streamErr.Error(),
			}})
		}

		finishStr := finishReason
		usage := map[string]any{
			"prompt_tokens":     inputTokens,
			"completion_tokens": outputTokens,
			"total_tokens":      inputTokens + outputTokens,
		}
		if cacheReadTokens > 0 || cacheWriteTokens > 0 {
			// OpenAI-style cache detail + explicit Bedrock counts
			usage["prompt_tokens_details"] = map[string]any{"cached_tokens": cacheReadTokens}
			usage["cache_read_input_tokens"] = cacheReadTokens
			usage["cache_write_input_tokens"] = cacheWriteTokens
		}
		sendSSE(makeChunk(map[string]any{}, &finishStr, usage))
		if finishReason != "error" {
			saveSession(fullText.String())
		}
		fmt.Fprintf(w, "data: [DONE]\n\n")
		if canFlush {
			flusher.Flush()
		}
		return
	}

	// ── Non-streaming: shared InvokeModel (with transient-error retry) ─────────
	bedrockOut, bedrockErr := h.invokeModelWithRetry(r.Context(), &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(awsModelID),
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
		Body:        payloadBytes,
	})

	// ── Non-streaming JSON response ────────────────────────────────────────────
	if bedrockErr != nil {
		respondError(w, http.StatusInternalServerError, "AI_ERROR", "failed to invoke bedrock model: "+bedrockErr.Error())
		return
	}
	output := bedrockOut

	type respMessage struct {
		Role      string           `json:"role"`
		Content   any              `json:"content"`
		ToolCalls []map[string]any `json:"tool_calls,omitempty"`
	}
	type openAIChoice struct {
		Index        int         `json:"index"`
		Message      respMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	}
	type openAIChatResponse struct {
		ID      string         `json:"id"`
		Object  string         `json:"object"`
		Created int64          `json:"created"`
		Model   string         `json:"model"`
		Choices []openAIChoice `json:"choices"`
	}

	if selected.isNova {
		var novaResp struct {
			StopReason string `json:"stopReason"`
			Output     struct {
				Message struct {
					Content []struct {
						Text    string `json:"text"`
						ToolUse *struct {
							ToolUseID string         `json:"toolUseId"`
							Name      string         `json:"name"`
							Input     map[string]any `json:"input"`
						} `json:"toolUse"`
					} `json:"content"`
				} `json:"message"`
			} `json:"output"`
		}
		if err := json.Unmarshal(output.Body, &novaResp); err != nil {
			respondError(w, http.StatusInternalServerError, "AI_ERROR", "failed to parse model response")
			return
		}
		finishReason := "stop"
		msg := respMessage{Role: "assistant"}
		if novaResp.StopReason == "tool_use" {
			finishReason = "tool_calls"
			msg.Content = nil
			for _, c := range novaResp.Output.Message.Content {
				if c.ToolUse != nil {
					argsJSON, _ := json.Marshal(c.ToolUse.Input)
					msg.ToolCalls = append(msg.ToolCalls, map[string]any{
						"id":   c.ToolUse.ToolUseID,
						"type": "function",
						"function": map[string]any{
							"name":      c.ToolUse.Name,
							"arguments": string(argsJSON),
						},
					})
				}
			}
		} else {
			var text string
			for _, c := range novaResp.Output.Message.Content {
				text += c.Text
			}
			msg.Content = text
			saveSession(text)
		}
		respondJSON(w, http.StatusOK, openAIChatResponse{
			ID: chatID, Object: "chat.completion", Created: created, Model: rawReq.Model,
			Choices: []openAIChoice{{Index: 0, Message: msg, FinishReason: finishReason}},
		})
	} else {
		var anthropicResp struct {
			StopReason string `json:"stop_reason"`
			Content    []struct {
				Type  string         `json:"type"`
				Text  string         `json:"text"`
				ID    string         `json:"id"`
				Name  string         `json:"name"`
				Input map[string]any `json:"input"`
			} `json:"content"`
		}
		if err := json.Unmarshal(output.Body, &anthropicResp); err != nil {
			respondError(w, http.StatusInternalServerError, "AI_ERROR", "failed to parse model response")
			return
		}
		finishReason := "stop"
		msg := respMessage{Role: "assistant"}
		if anthropicResp.StopReason == "tool_use" {
			finishReason = "tool_calls"
			msg.Content = nil
			for _, c := range anthropicResp.Content {
				if c.Type == "tool_use" {
					argsJSON, _ := json.Marshal(c.Input)
					msg.ToolCalls = append(msg.ToolCalls, map[string]any{
						"id": c.ID, "type": "function",
						"function": map[string]any{"name": c.Name, "arguments": string(argsJSON)},
					})
				}
			}
		} else {
			var text string
			for _, c := range anthropicResp.Content {
				if c.Type == "text" {
					text += c.Text
				}
			}
			msg.Content = text
			saveSession(text)
		}
		respondJSON(w, http.StatusOK, openAIChatResponse{
			ID: chatID, Object: "chat.completion", Created: created, Model: rawReq.Model,
			Choices: []openAIChoice{{Index: 0, Message: msg, FinishReason: finishReason}},
		})
	}
}

// Generate Dockerfile
func (h *AIHandler) Dockerfile(w http.ResponseWriter, r *http.Request) {
	if h.aws == nil {
		respondError(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI features require AWS Bedrock configuration")
		return
	}

	var req struct {
		Runtime string `json:"runtime"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	prompt := fmt.Sprintf("Generate an optimized multi-stage build Dockerfile for a production app using runtime: %s. Respond ONLY with the Dockerfile contents inside a fenced code block.", req.Runtime)
	responseText, err := callBedrock(r.Context(), h.aws, prompt)
	if err != nil {
		h.logger.Warn("bedrock dockerfile generation failed", "error", err)
		respondError(w, http.StatusServiceUnavailable, "AI_ERROR", "AI request failed: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"dockerfile": responseText})
}

// Explain Build Failure
func (h *AIHandler) ExplainFailure(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeploymentID string `json:"deployment_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	depID, err := uuid.Parse(req.DeploymentID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid deployment id")
		return
	}

	logs, err := h.depsRepo.GetLogs(r.Context(), depID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to retrieve deployment logs")
		return
	}

	var logsStr []string
	for _, l := range logs {
		logsStr = append(logsStr, fmt.Sprintf("[%s] %s: %s", l.CreatedAt.Format(time.RFC3339), l.Level, l.Message))
	}

	fullLogs := strings.Join(logsStr, "\n")
	if fullLogs == "" {
		fullLogs = "No build logs available."
	}

	if h.aws == nil {
		respondError(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI features require AWS Bedrock configuration")
		return
	}

	prompt := fmt.Sprintf("Review the following deployment build logs and explain the failure in a clean, developer-focused summary, suggesting immediate fixes:\n\n%s", fullLogs)
	explanation, err := callBedrock(r.Context(), h.aws, prompt)
	if err != nil {
		h.logger.Warn("bedrock explain-failure failed", "error", err)
		respondError(w, http.StatusServiceUnavailable, "AI_ERROR", "AI request failed: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"explanation": explanation})
}

// Suggest Cost Optimization
func (h *AIHandler) OptimizeCosts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	projID, err := uuid.Parse(req.ProjectID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid project id")
		return
	}

	project, err := h.projects.GetByID(r.Context(), projID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to retrieve project details")
		return
	}

	if h.aws == nil {
		respondError(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI features require AWS Bedrock configuration")
		return
	}

	prompt := fmt.Sprintf("Analyze the active cloud infrastructure configuration for the project '%s' (Runtime: %s, Container Replicas: %d, Serverless Deployed: %t). Provide immediate cost-saving recommendations (e.g. switching to serverless Lambda, auto-scaling cooldown times, RDS sizing) formatted beautifully as developer-ready markdown advice.",
		project.Name, project.Runtime, project.Replicas, project.Serverless)

	recommendations, err := callBedrock(r.Context(), h.aws, prompt)
	if err != nil {
		h.logger.Warn("bedrock optimize-costs failed", "error", err)
		respondError(w, http.StatusServiceUnavailable, "AI_ERROR", "AI request failed: "+err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"recommendations": recommendations})
}

// Helpers
func hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

// callBedrock invokes Amazon Nova Lite via Bedrock (no Anthropic approval required).
// Returns the model response text or an error — no mock fallback.
func callBedrock(ctx context.Context, awsClients *awsclient.Clients, prompt string) (string, error) {
	novaPayload := map[string]any{
		"messages": []map[string]any{
			{
				"role":    "user",
				"content": []map[string]any{{"text": prompt}},
			},
		},
		"inferenceConfig": map[string]any{"maxTokens": 2000},
	}

	payloadBytes, _ := json.Marshal(novaPayload)

	output, err := awsClients.Bedrock.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String("amazon.nova-lite-v1:0"),
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
		Body:        payloadBytes,
	})
	if err != nil {
		return "", fmt.Errorf("bedrock invoke: %w", err)
	}

	var novaResp struct {
		Output struct {
			Message struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"message"`
		} `json:"output"`
	}
	if err := json.Unmarshal(output.Body, &novaResp); err != nil {
		return "", fmt.Errorf("parsing bedrock response: %w", err)
	}
	if len(novaResp.Output.Message.Content) == 0 {
		return "", fmt.Errorf("empty response from bedrock")
	}
	return novaResp.Output.Message.Content[0].Text, nil
}
