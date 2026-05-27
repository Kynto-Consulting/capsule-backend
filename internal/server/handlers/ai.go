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
			ID: "claude-haiku-4.5", Name: "Claude Haiku 4.5", Provider: "Anthropic",
			BedrockID: "us.anthropic.claude-3-5-haiku-20241022-v1:0",
			ContextWindow: 200000, MaxOutput: 8192,
			Description: "Fastest and most compact Claude model. Ideal for classification, extraction, and simple Q&A at high throughput.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, FunctionCalling: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.00025, OutputPer1KTokens: 0.00125},
			Tags:         []string{"fast", "cheap", "classification"},
		},
		{
			ID: "claude-sonnet-4", Name: "Claude Sonnet 4", Provider: "Anthropic",
			BedrockID: "us.anthropic.claude-sonnet-4-5:0",
			ContextWindow: 200000, MaxOutput: 16000,
			Description: "Best balance of intelligence and speed. Recommended for most production workloads including reasoning, coding, and analysis.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, VisionAnalysis: true, FunctionCalling: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.003, OutputPer1KTokens: 0.015},
			Tags:         []string{"balanced", "vision", "recommended"},
		},
		{
			ID: "claude-opus-4", Name: "Claude Opus 4", Provider: "Anthropic",
			BedrockID: "us.anthropic.claude-opus-4-5:0",
			ContextWindow: 200000, MaxOutput: 32000,
			Description: "Most powerful Claude model. Best for complex reasoning, research synthesis, and tasks requiring deep analysis.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, VisionAnalysis: true, FunctionCalling: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.015, OutputPer1KTokens: 0.075},
			Tags:         []string{"powerful", "complex-reasoning", "research"},
		},
		{
			ID: "titan-text-express", Name: "Amazon Titan Text Express", Provider: "Amazon",
			BedrockID: "amazon.titan-text-express-v1",
			ContextWindow: 8192, MaxOutput: 8192,
			Description: "Amazon's general-purpose text model. Cost-effective for summarisation, paraphrase, and open-ended generation.",
			Capabilities: ModelCapabilities{TextGeneration: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.0002, OutputPer1KTokens: 0.0006},
			Tags:         []string{"amazon", "budget"},
		},
		{
			ID: "llama3-70b", Name: "Meta Llama 3 70B Instruct", Provider: "Meta",
			BedrockID: "us.meta.llama3-70b-instruct-v1:0",
			ContextWindow: 128000, MaxOutput: 8192,
			Description: "Meta's flagship open model. Strong performance on instruction-following, coding assistance, and multilingual tasks.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.00265, OutputPer1KTokens: 0.0035},
			Tags:         []string{"open-source", "multilingual"},
		},
		{
			ID: "mistral-7b", Name: "Mistral 7B Instruct", Provider: "Mistral AI",
			BedrockID: "mistral.mistral-7b-instruct-v0:2",
			ContextWindow: 32768, MaxOutput: 8192,
			Description: "Efficient 7B model with strong reasoning relative to size. Good for low-latency workloads with moderate complexity.",
			Capabilities: ModelCapabilities{TextGeneration: true, CodeGeneration: true, Streaming: true},
			Pricing:      ModelPricing{InputPer1KTokens: 0.00015, OutputPer1KTokens: 0.0002},
			Tags:         []string{"efficient", "low-latency"},
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

	// Map models — use cross-region inference profile IDs (us.* prefix required for on-demand)
	awsModelID := "us.anthropic.claude-sonnet-4-5:0"
	switch req.Model {
	case "claude-haiku-4.5":
		awsModelID = "us.anthropic.claude-3-5-haiku-20241022-v1:0"
	case "claude-opus-4":
		awsModelID = "us.anthropic.claude-opus-4-5:0"
	case "titan-text-express":
		awsModelID = "amazon.titan-text-express-v1"
	case "llama3-70b":
		awsModelID = "us.meta.llama3-70b-instruct-v1:0"
	case "mistral-7b":
		awsModelID = "mistral.mistral-7b-instruct-v0:2"
	}

	// Build Anthropic messages payload
	type bedrockMsg struct {
		Role    string `json:"role"`
		Content []map[string]any `json:"content"`
	}

	var systemPrompt string
	var bedrockMessages []bedrockMsg

	for _, m := range req.Messages {
		if m.Role == "system" {
			systemPrompt = m.Content
			continue
		}
		
		bedrockMessages = append(bedrockMessages, bedrockMsg{
			Role: m.Role,
			Content: []map[string]any{
				{
					"type": "text",
					"text": m.Content,
				},
			},
		})
	}

	bedrockPayload := map[string]any{
		"anthropic_version": "bedrock-2023-05-31",
		"max_tokens":        2000,
		"messages":          bedrockMessages,
	}
	if systemPrompt != "" {
		bedrockPayload["system"] = systemPrompt
	}

	payloadBytes, _ := json.Marshal(bedrockPayload)

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

		var bedrockResponse struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(output.Body, &bedrockResponse); err == nil && len(bedrockResponse.Content) > 0 {
			aiResponseText = bedrockResponse.Content[0].Text
		} else {
			aiResponseText = "Received empty response from Claude Bedrock client."
		}
	} else {
		// Mock responses for local dev when Bedrock credentials aren't loaded
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
	if strings.Contains(lower, "build log") || strings.Contains(lower, "fail") {
		return `### Build Failure Analysis 🔍

**Reason:** The build failed during Go package dependency downloading due to an invalid package path in ` + "`" + `go.mod` + "`" + `.

**Error Log Snippet:**
` + "```" + `
go: kynto/capsule/broken-pkg@v1.0.0: malformed module path
` + "```" + `

**Recommended Fixes:**
1. Check ` + "`" + `go.mod` + "`" + ` at line 14 and verify the path to dependencies.
2. Run ` + "`" + `go mod tidy` + "`" + ` locally to clean up the module structure.
3. Commit and push the updated dependencies.`
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
