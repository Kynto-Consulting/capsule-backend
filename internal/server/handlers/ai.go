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
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
	"github.com/kynto/capsule/backend/pkg/awsclient"
)

type AIHandler struct {
	tokens   domain.APITokenRepository
	orgs     domain.OrganizationRepository
	projects domain.ProjectRepository
	depsRepo domain.DeploymentRepository
	aws      *awsclient.Clients
	logger   *slog.Logger
	authSvc  domain.AuthService
}

func NewAIHandler(
	tokens domain.APITokenRepository,
	orgs domain.OrganizationRepository,
	projects domain.ProjectRepository,
	depsRepo domain.DeploymentRepository,
	awsClients *awsclient.Clients,
	logger *slog.Logger,
	authSvc domain.AuthService,
) *AIHandler {
	return &AIHandler{
		tokens:   tokens,
		orgs:     orgs,
		projects: projects,
		depsRepo: depsRepo,
		aws:      awsClients,
		logger:   logger,
		authSvc:  authSvc,
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
			BedrockID: "amazon.nova-pro-v1:0",
			ContextWindow: 300000, MaxOutput: 5120,
			Description: "Amazon's most capable multimodal model. Handles complex text, images, and video with high accuracy. No approval required.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, VisionAnalysis: true, FunctionCalling: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.0008, OutputPer1KTokens: 0.0032},
			Tags:         []string{"amazon", "multimodal", "available"},
		},
		{
			ID: "nova-lite", Name: "Amazon Nova Lite", Provider: "Amazon",
			BedrockID: "amazon.nova-lite-v1:0",
			ContextWindow: 300000, MaxOutput: 5120,
			Description: "Fast and cost-effective multimodal model. Great for summarisation, Q&A, and light reasoning tasks.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, VisionAnalysis: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.00006, OutputPer1KTokens: 0.00024},
			Tags:         []string{"amazon", "fast", "cheap", "available"},
		},
		{
			ID: "nova-micro", Name: "Amazon Nova Micro", Provider: "Amazon",
			BedrockID: "amazon.nova-micro-v1:0",
			ContextWindow: 128000, MaxOutput: 5120,
			Description: "Smallest and fastest Nova model. Optimised for text tasks at ultra-low cost.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.000035, OutputPer1KTokens: 0.00014},
			Tags:         []string{"amazon", "ultra-fast", "cheapest", "available"},
		},
		{
			ID: "claude-haiku-4.5", Name: "Claude Haiku 4.5", Provider: "Anthropic",
			BedrockID: "us.anthropic.claude-haiku-4-5-20251001-v1:0",
			ContextWindow: 200000, MaxOutput: 8192,
			Description: "Fastest and most compact Claude model. Ideal for classification, extraction, and simple Q&A at high throughput.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, FunctionCalling: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.00025, OutputPer1KTokens: 0.00125},
			Tags:         []string{"fast", "cheap", "classification"},
		},
		{
			ID: "claude-sonnet-4.5", Name: "Claude Sonnet 4.5", Provider: "Anthropic",
			BedrockID: "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
			ContextWindow: 200000, MaxOutput: 16000,
			Description: "Best balance of intelligence and speed. Recommended for most production workloads including reasoning, coding, and analysis.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, VisionAnalysis: true, FunctionCalling: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.003, OutputPer1KTokens: 0.015},
			Tags:         []string{"balanced", "vision", "recommended"},
		},
		{
			ID: "claude-opus-4.5", Name: "Claude Opus 4.5", Provider: "Anthropic",
			BedrockID: "us.anthropic.claude-opus-4-5-20251101-v1:0",
			ContextWindow: 200000, MaxOutput: 32000,
			Description: "Most powerful Claude model. Best for complex reasoning, research synthesis, and tasks requiring deep analysis.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, VisionAnalysis: true, FunctionCalling: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.015, OutputPer1KTokens: 0.075},
			Tags:         []string{"powerful", "complex-reasoning", "research"},
		},
		{
			ID: "llama3-3-70b", Name: "Meta Llama 3.3 70B Instruct", Provider: "Meta",
			BedrockID: "us.meta.llama3-3-70b-instruct-v1:0",
			ContextWindow: 128000, MaxOutput: 8192,
			Description: "Meta's latest open model. Strong instruction-following, coding assistance, and multilingual support.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.00099, OutputPer1KTokens: 0.00099},
			Tags:         []string{"open-source", "multilingual"},
		},
		{
			ID: "llama3-2-90b", Name: "Meta Llama 3.2 90B Instruct", Provider: "Meta",
			BedrockID: "us.meta.llama3-2-90b-instruct-v1:0",
			ContextWindow: 128000, MaxOutput: 8192,
			Description: "Large vision-capable Llama model for complex reasoning and image understanding tasks.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, VisionAnalysis: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.00072, OutputPer1KTokens: 0.00072},
			Tags:         []string{"open-source", "vision"},
		},
		{
			ID: "deepseek-r1", Name: "DeepSeek-R1", Provider: "DeepSeek",
			BedrockID: "us.deepseek.r1-v1:0",
			ContextWindow: 64000, MaxOutput: 8192,
			Description: "Advanced reasoning model with extended chain-of-thought. Excellent for math, logic, and complex problem solving.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.00135, OutputPer1KTokens: 0.0054},
			Tags:         []string{"reasoning", "math", "chain-of-thought"},
		},
	}

	respondJSON(w, http.StatusOK, map[string]any{"data": models})
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

	type chatMessage struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}

	var req struct {
		Model    string        `json:"model"`
		Messages []chatMessage `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if len(req.Messages) == 0 {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "messages cannot be empty")
		return
	}

	// Map model IDs — Nova models available without use-case form; Claude requires Anthropic approval
	type modelDef struct {
		bedrockID string
		isNova    bool
	}
	modelMap := map[string]modelDef{
		"nova-pro":       {"amazon.nova-pro-v1:0", true},
		"nova-lite":      {"amazon.nova-lite-v1:0", true},
		"nova-micro":     {"amazon.nova-micro-v1:0", true},
		"claude-haiku-4.5":  {"us.anthropic.claude-haiku-4-5-20251001-v1:0", false},
		"claude-sonnet-4.5": {"us.anthropic.claude-sonnet-4-5-20250929-v1:0", false},
		"claude-opus-4.5":   {"us.anthropic.claude-opus-4-5-20251101-v1:0", false},
		"llama3-3-70b":      {"us.meta.llama3-3-70b-instruct-v1:0", false},
		"llama3-2-90b":      {"us.meta.llama3-2-90b-instruct-v1:0", false},
		"deepseek-r1":       {"us.deepseek.r1-v1:0", false},
	}
	selected, ok := modelMap[req.Model]
	if !ok {
		selected = modelDef{"amazon.nova-lite-v1:0", true}
	}
	awsModelID := selected.bedrockID

	// Build payload — Nova uses a different schema from Anthropic
	type bedrockMsg struct {
		Role    string           `json:"role"`
		Content []map[string]any `json:"content"`
	}

	var systemPrompt string
	var bedrockMessages []bedrockMsg

	var novaMessages []bedrockMsg
	for _, m := range req.Messages {
		if m.Role == "system" {
			systemPrompt = m.Content
			continue
		}
		// Anthropic format: {"type":"text","text":"..."}  Nova format: {"text":"..."}
		bedrockMessages = append(bedrockMessages, bedrockMsg{
			Role:    m.Role,
			Content: []map[string]any{{"type": "text", "text": m.Content}},
		})
		novaMessages = append(novaMessages, bedrockMsg{
			Role:    m.Role,
			Content: []map[string]any{{"text": m.Content}},
		})
	}

	var payloadBytes []byte
	if selected.isNova {
		novaPayload := map[string]any{
			"messages":        novaMessages,
			"inferenceConfig": map[string]any{"maxTokens": 2000},
		}
		if systemPrompt != "" {
			novaPayload["system"] = []map[string]any{{"text": systemPrompt}}
		}
		payloadBytes, _ = json.Marshal(novaPayload)
	} else {
		anthropicPayload := map[string]any{
			"anthropic_version": "bedrock-2023-05-31",
			"max_tokens":        2000,
			"messages":          bedrockMessages,
		}
		if systemPrompt != "" {
			anthropicPayload["system"] = systemPrompt
		}
		payloadBytes, _ = json.Marshal(anthropicPayload)
	}

	var aiResponseText string

	if h.aws != nil {
		output, err := h.aws.Bedrock.InvokeModel(r.Context(), &bedrockruntime.InvokeModelInput{
			ModelId:     aws.String(awsModelID),
			ContentType: aws.String("application/json"),
			Accept:      aws.String("application/json"),
			Body:        payloadBytes,
		})
		if err != nil {
			respondError(w, http.StatusInternalServerError, "AI_ERROR", "failed to invoke bedrock model: "+err.Error())
			return
		}

		if selected.isNova {
			var novaResp struct {
				Output struct {
					Message struct {
						Content []struct{ Text string `json:"text"` } `json:"content"`
					} `json:"message"`
				} `json:"output"`
			}
			if err := json.Unmarshal(output.Body, &novaResp); err == nil &&
				len(novaResp.Output.Message.Content) > 0 {
				aiResponseText = novaResp.Output.Message.Content[0].Text
			}
		} else {
			var anthropicResp struct {
				Content []struct{ Text string `json:"text"` } `json:"content"`
			}
			if err := json.Unmarshal(output.Body, &anthropicResp); err == nil &&
				len(anthropicResp.Content) > 0 {
				aiResponseText = anthropicResp.Content[0].Text
			}
		}
		if aiResponseText == "" {
			aiResponseText = "Received empty response from model."
		}
	} else {
		aiResponseText = getMockAIResponse(req.Messages[len(req.Messages)-1].Content)
	}

	// Format as OpenAI Chat Completion response
	type openAIChoice struct {
		Index        int         `json:"index"`
		Message      chatMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	}
	type openAIChatResponse struct {
		ID      string         `json:"id"`
		Object  string         `json:"object"`
		Created int64          `json:"created"`
		Model   string         `json:"model"`
		Choices []openAIChoice `json:"choices"`
	}

	respondJSON(w, http.StatusOK, openAIChatResponse{
		ID:      "chatcmpl-" + randomString(12),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   req.Model,
		Choices: []openAIChoice{
			{
				Index:        0,
				Message:      chatMessage{Role: "assistant", Content: aiResponseText},
				FinishReason: "stop",
			},
		},
	})
}

// Generate Dockerfile
func (h *AIHandler) Dockerfile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Runtime string `json:"runtime"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	prompt := fmt.Sprintf("Generate an optimized multi-stage build Dockerfile for a production app using runtime: %s. Respond ONLY with the Dockerfile contents inside a fenced code block.", req.Runtime)
	responseText := callMockOrRealClaude(r.Context(), h.aws, prompt)

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

	prompt := fmt.Sprintf("Review the following deployment build logs and explain the failure in a clean, developer-focused summary, suggesting immediate fixes:\n\n%s", fullLogs)
	explanation := callMockOrRealClaude(r.Context(), h.aws, prompt)

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

	prompt := fmt.Sprintf("Analyze the active cloud infrastructure configuration for the project '%s' (Runtime: %s, Container Replicas: %d, Serverless Deployed: %t). Provide immediate cost-saving recommendations (e.g. switching to serverless Lambda, auto-scaling cooldown times, RDS sizing) formatted beautifully as developer-ready markdown advice.",
		project.Name, project.Runtime, project.Replicas, project.Serverless)
	
	recommendations := callMockOrRealClaude(r.Context(), h.aws, prompt)

	respondJSON(w, http.StatusOK, map[string]string{"recommendations": recommendations})
}

// Helpers
func hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

func callMockOrRealClaude(ctx context.Context, awsClients *awsclient.Clients, prompt string) string {
	if awsClients == nil {
		return getMockAIResponse(prompt)
	}

	bedrockMessages := []map[string]any{
		{
			"role": "user",
			"content": []map[string]any{
				{
					"type": "text",
					"text": prompt,
				},
			},
		},
	}

	bedrockPayload := map[string]any{
		"anthropic_version": "bedrock-2023-05-31",
		"max_tokens":        2000,
		"messages":          bedrockMessages,
	}

	payloadBytes, _ := json.Marshal(bedrockPayload)

	output, err := awsClients.Bedrock.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String("anthropic.claude-3-5-sonnet-20241022-v2:0"),
		ContentType: aws.String("application/json"),
		Accept:      aws.String("application/json"),
		Body:        payloadBytes,
	})
	if err != nil {
		slog.Warn("Bedrock invoke failed, falling back to mock response", "error", err)
		return getMockAIResponse(prompt)
	}

	var bedrockResponse struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(output.Body, &bedrockResponse); err == nil && len(bedrockResponse.Content) > 0 {
		return bedrockResponse.Content[0].Text
	}
	return "No text response found from Claude Bedrock client."
}

func getMockAIResponse(userPrompt string) string {
	lower := strings.ToLower(userPrompt)
	if strings.Contains(lower, "dockerfile") {
		switch {
		case strings.Contains(lower, "node"):
			return `# Stage 1: Build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

# Stage 2: Production image
FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
EXPOSE 3000
CMD ["node", "dist/index.js"]`
		case strings.Contains(lower, "python"):
			return `# Stage 1: Build
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt
COPY . .

# Stage 2: Production image
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=builder /install /usr/local
COPY --from=builder /app .
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]`
		case strings.Contains(lower, "rust"):
			return `# Stage 1: Build
FROM rust:1.77-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.* ./
RUN mkdir src && echo "fn main(){}" > src/main.rs && cargo build --release
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Stage 2: Final minimal image
FROM scratch
COPY --from=builder /app/target/release/app /app
EXPOSE 8080
ENTRYPOINT ["/app"]`
		default: // go
			return `# Stage 1: Build
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w" -o server ./cmd/server

# Stage 2: Final minimal image
FROM scratch
WORKDIR /
COPY --from=builder /app/server /server
EXPOSE 8080
ENTRYPOINT ["/server"]`
		}
	}
	if strings.Contains(lower, "build log") || strings.Contains(lower, "fail") {
		// Extract actual error lines from the prompt (which contains real build logs)
		var errorLines []string
		for _, line := range strings.Split(userPrompt, "\n") {
			l := strings.ToLower(line)
			if strings.Contains(l, "[error]") || strings.Contains(l, "error:") ||
				strings.Contains(l, "failed") || strings.Contains(l, "non-zero code") ||
				strings.Contains(l, "exit status") || strings.Contains(l, "unexpected") {
				trimmed := strings.TrimSpace(line)
				if trimmed != "" {
					errorLines = append(errorLines, trimmed)
				}
			}
		}

		snippet := "No specific error lines detected in logs."
		if len(errorLines) > 0 {
			if len(errorLines) > 4 {
				errorLines = errorLines[:4]
			}
			snippet = strings.Join(errorLines, "\n")
		}

		return fmt.Sprintf(`### Build Failure Analysis 🔍

**Detected Error(s):**
`+"```"+`
%s
`+"```"+`

**Recommended Fixes:**
1. Review the error above — it points to the root cause.
2. Check your Dockerfile, dependency files, and source code for typos or missing files.
3. Run the build command locally to reproduce and fix the issue.
4. Ensure all required files are included in your source archive.`, snippet)
	}
	if strings.Contains(lower, "optimize") || strings.Contains(lower, "cost") {
		return `### Cost Optimization Recommendation 💡

Based on your configuration, switching to **Serverless Lambda** deployments can immediately trim down your recurring costs.

**Current Cost Overview:**
- EC2 t3.small Serverless Container: ~$15.00/month
- Shared ALB segment: ~$22.00/month
- Total: **~$37.00/month**

**Optimized Cost Overview:**
- Switching to AWS Lambda for request-driven load (assuming 1M request average):
- Lambda execution charges: ~$0.20/month
- API Gateway charges: ~$3.50/month
- Total: **~$3.70/month**

**Net Monthly Savings:** **~90% savings ($33.30/month saved!)**`
	}

	return "Hi there! I am your Capsule Bedrock AI Assistant. I can help you configure Dockerfiles, analyze failed builds, verify Route53 setups, or calculate the exact monthly pricing of your ECS replicas. What can I help you build?"
}
