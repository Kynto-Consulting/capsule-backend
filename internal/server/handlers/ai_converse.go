package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	bedrockdoc "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/document"
	bt "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

// bedrockMsg is the map-based intermediate message used by both the raw
// invoke_model path and the Converse path.
type bedrockMsg struct {
	Role    string           `json:"role"`
	Content []map[string]any `json:"content"`
}

// converseNovaArgs carries everything converseNova needs, built from the same
// map-based intermediate representation the raw path uses — so all role / tool /
// image parsing logic is reused, only the final serialization differs.
type converseNovaArgs struct {
	modelID      string
	systemPrompt string
	novaMessages []bedrockMsg // {Role, Content:[]map[string]any} — text/image/toolUse/toolResult blocks
	tools        []map[string]any
	toolChoice   map[string]any // {"auto":{}} / {"any":{}}
	stream       bool
	cacheSystem  bool
	cacheHistIdx int // index in novaMessages to attach a history cachePoint to (-1 = none)
	chatID       string
	created      int64
	model        string // echoed back in the OpenAI response
	saveSession  func(string)
}

// buildConverseMessages converts the map-based novaMessages into typed
// Converse messages, attaching a history cachePoint at cacheHistIdx if set.
func buildConverseMessages(a converseNovaArgs) []bt.Message {
	msgs := make([]bt.Message, 0, len(a.novaMessages))
	for i, m := range a.novaMessages {
		role := bt.ConversationRoleUser
		if m.Role == "assistant" {
			role = bt.ConversationRoleAssistant
		}
		var blocks []bt.ContentBlock
		for _, blk := range m.Content {
			switch {
			case blk["text"] != nil:
				if s, ok := blk["text"].(string); ok {
					blocks = append(blocks, &bt.ContentBlockMemberText{Value: s})
				}
			case blk["image"] != nil:
				if img, ok := blk["image"].(map[string]any); ok {
					format, _ := img["format"].(string)
					if src, ok := img["source"].(map[string]any); ok {
						if b64, ok := src["bytes"].(string); ok {
							if raw, err := base64.StdEncoding.DecodeString(b64); err == nil {
								blocks = append(blocks, &bt.ContentBlockMemberImage{Value: bt.ImageBlock{
									Format: bt.ImageFormat(format),
									Source: &bt.ImageSourceMemberBytes{Value: raw},
								}})
							}
						}
					}
				}
			case blk["toolUse"] != nil:
				if tu, ok := blk["toolUse"].(map[string]any); ok {
					id, _ := tu["toolUseId"].(string)
					name, _ := tu["name"].(string)
					blocks = append(blocks, &bt.ContentBlockMemberToolUse{Value: bt.ToolUseBlock{
						ToolUseId: aws.String(id),
						Name:      aws.String(name),
						Input:     bedrockdoc.NewLazyDocument(tu["input"]),
					}})
				}
			case blk["toolResult"] != nil:
				if tr, ok := blk["toolResult"].(map[string]any); ok {
					id, _ := tr["toolUseId"].(string)
					var rc []bt.ToolResultContentBlock
					if cs, ok := tr["content"].([]map[string]any); ok {
						for _, c := range cs {
							if t, ok := c["text"].(string); ok {
								rc = append(rc, &bt.ToolResultContentBlockMemberText{Value: t})
							}
						}
					}
					blocks = append(blocks, &bt.ContentBlockMemberToolResult{Value: bt.ToolResultBlock{
						ToolUseId: aws.String(id),
						Content:   rc,
					}})
				}
			}
		}
		// History cachePoint: append after this message's content blocks.
		if a.cacheHistIdx >= 0 && i == a.cacheHistIdx && len(blocks) > 0 {
			blocks = append(blocks, &bt.ContentBlockMemberCachePoint{
				Value: bt.CachePointBlock{Type: bt.CachePointTypeDefault},
			})
		}
		if len(blocks) > 0 {
			msgs = append(msgs, bt.Message{Role: role, Content: blocks})
		}
	}
	return msgs
}

func buildConverseSystem(a converseNovaArgs) []bt.SystemContentBlock {
	if a.systemPrompt == "" {
		return nil
	}
	sys := []bt.SystemContentBlock{&bt.SystemContentBlockMemberText{Value: a.systemPrompt}}
	if a.cacheSystem {
		sys = append(sys, &bt.SystemContentBlockMemberCachePoint{
			Value: bt.CachePointBlock{Type: bt.CachePointTypeDefault},
		})
	}
	return sys
}

func buildConverseTools(a converseNovaArgs) *bt.ToolConfiguration {
	if len(a.tools) == 0 {
		return nil
	}
	var tools []bt.Tool
	for _, t := range a.tools {
		ts, ok := t["toolSpec"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := ts["name"].(string)
		desc, _ := ts["description"].(string)
		var schema any
		if is, ok := ts["inputSchema"].(map[string]any); ok {
			schema = is["json"]
		}
		spec := bt.ToolSpecification{
			Name:        aws.String(name),
			InputSchema: &bt.ToolInputSchemaMemberJson{Value: bedrockdoc.NewLazyDocument(schema)},
		}
		if desc != "" {
			spec.Description = aws.String(desc)
		}
		tools = append(tools, &bt.ToolMemberToolSpec{Value: spec})
	}
	if len(tools) == 0 {
		return nil
	}
	cfg := &bt.ToolConfiguration{Tools: tools}
	if a.toolChoice["any"] != nil {
		cfg.ToolChoice = &bt.ToolChoiceMemberAny{}
	} else {
		cfg.ToolChoice = &bt.ToolChoiceMemberAuto{}
	}
	return cfg
}

// converseNova runs a Nova request through the Converse API (which, unlike raw
// invoke_model, supports prompt caching via cachePoint).
// fallbackModelIDs returns sibling Bedrock model IDs to try when the primary
// model fails with a transient error (throttling / 5xx). Ordered best-first.
// Keeps the same provider family where possible, ending on the always-cheap
// Nova Lite as a last resort so a request rarely dies on throttling.
func fallbackModelIDs(primary string) []string {
	const (
		sonnet    = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
		haiku     = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
		novaLite  = "amazon.nova-lite-v1:0"
		novaMicro = "amazon.nova-micro-v1:0"
	)
	switch {
	case strings.Contains(primary, "opus"):
		return []string{sonnet, haiku, novaLite}
	case strings.Contains(primary, "sonnet"):
		return []string{haiku, novaLite}
	case strings.Contains(primary, "haiku"):
		return []string{novaLite}
	case strings.Contains(primary, "nova-pro"), strings.Contains(primary, "nova-lite"):
		return []string{novaMicro}
	case strings.Contains(primary, "deepseek"), strings.Contains(primary, "llama"):
		return []string{novaLite}
	default:
		return nil
	}
}

// converseWithFallback calls Converse, retrying the primary model on transient
// errors, then falling back to sibling models. Returns the output and the model
// actually used.
func (h *AIHandler) converseWithFallback(ctx context.Context, in *bedrockruntime.ConverseInput) (*bedrockruntime.ConverseOutput, string, error) {
	primary := aws.ToString(in.ModelId)
	models := append([]string{primary}, fallbackModelIDs(primary)...)
	var lastErr error
	for mi, model := range models {
		in.ModelId = aws.String(model)
		// Retry each model up to 3x on transient errors before moving on.
		for attempt := 0; attempt < 3; attempt++ {
			out, err := h.aws.Bedrock.Converse(ctx, in)
			if err == nil {
				return out, model, nil
			}
			lastErr = err
			if !isTransientBedrockError(err) {
				break // hard error (bad request, unsupported) — don't retry/fallback-loop
			}
			if h.logger != nil {
				h.logger.Warn("converse transient error", "model", model, "attempt", attempt+1, "err", err.Error())
			}
			select {
			case <-ctx.Done():
				return nil, model, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 400 * time.Millisecond):
			}
		}
		if mi < len(models)-1 && h.logger != nil {
			h.logger.Warn("converse falling back to next model", "from", model, "to", models[mi+1])
		}
	}
	return nil, primary, lastErr
}

func (h *AIHandler) converseNova(ctx context.Context, w http.ResponseWriter, r *http.Request, a converseNovaArgs) {
	maxTokens := int32(4096)
	messages := buildConverseMessages(a)
	system := buildConverseSystem(a)
	toolCfg := buildConverseTools(a)
	infCfg := &bt.InferenceConfiguration{MaxTokens: aws.Int32(maxTokens)}

	if a.stream {
		h.converseNovaStream(ctx, w, a, messages, system, toolCfg, infCfg)
		return
	}

	out, _, err := h.converseWithFallback(ctx, &bedrockruntime.ConverseInput{
		ModelId:         aws.String(a.modelID),
		Messages:        messages,
		System:          system,
		ToolConfig:      toolCfg,
		InferenceConfig: infCfg,
	})
	if err != nil {
		respondError(w, http.StatusInternalServerError, "AI_ERROR", "converse failed: "+err.Error())
		return
	}

	type respMessage struct {
		Role      string           `json:"role"`
		Content   any              `json:"content"`
		ToolCalls []map[string]any `json:"tool_calls,omitempty"`
	}
	type choice struct {
		Index        int         `json:"index"`
		Message      respMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	}

	msg := respMessage{Role: "assistant"}
	finishReason := "stop"
	var text string

	if mo, ok := out.Output.(*bt.ConverseOutputMemberMessage); ok {
		for _, c := range mo.Value.Content {
			switch cb := c.(type) {
			case *bt.ContentBlockMemberText:
				text += cb.Value
			case *bt.ContentBlockMemberToolUse:
				finishReason = "tool_calls"
				var argsJSON []byte
				if cb.Value.Input != nil {
					argsJSON, _ = cb.Value.Input.MarshalSmithyDocument()
				}
				msg.ToolCalls = append(msg.ToolCalls, map[string]any{
					"id":   aws.ToString(cb.Value.ToolUseId),
					"type": "function",
					"function": map[string]any{
						"name":      aws.ToString(cb.Value.Name),
						"arguments": string(argsJSON),
					},
				})
			}
		}
	}
	if out.StopReason == bt.StopReasonToolUse {
		finishReason = "tool_calls"
	}
	if len(msg.ToolCalls) > 0 {
		msg.Content = nil
	} else {
		msg.Content = text
		a.saveSession(text)
	}

	usage := map[string]any{}
	if out.Usage != nil {
		in, o := int(aws.ToInt32(out.Usage.InputTokens)), int(aws.ToInt32(out.Usage.OutputTokens))
		usage["prompt_tokens"] = in
		usage["completion_tokens"] = o
		usage["total_tokens"] = in + o
		if cr := int(aws.ToInt32(out.Usage.CacheReadInputTokens)); cr > 0 {
			usage["prompt_tokens_details"] = map[string]any{"cached_tokens": cr}
			usage["cache_read_input_tokens"] = cr
		}
		if cw := int(aws.ToInt32(out.Usage.CacheWriteInputTokens)); cw > 0 {
			usage["cache_write_input_tokens"] = cw
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"id": a.chatID, "object": "chat.completion", "created": a.created, "model": a.model,
		"choices": []choice{{Index: 0, Message: msg, FinishReason: finishReason}},
		"usage":   usage,
	})
}

// converseNovaStream handles the SSE streaming path via ConverseStream.
func (h *AIHandler) converseNovaStream(ctx context.Context, w http.ResponseWriter, a converseNovaArgs,
	messages []bt.Message, system []bt.SystemContentBlock, toolCfg *bt.ToolConfiguration, infCfg *bt.InferenceConfiguration) {

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
	makeChunk := func(delta map[string]any, finish *string, usage map[string]any) map[string]any {
		ch := map[string]any{"index": 0, "delta": delta, "finish_reason": finish}
		out := map[string]any{
			"id": a.chatID, "object": "chat.completion.chunk",
			"created": a.created, "model": a.model, "choices": []any{ch},
		}
		if usage != nil {
			out["usage"] = usage
		}
		return out
	}

	// Open the stream, retrying the primary model on transient errors then
	// falling back to sibling models — all before any bytes are written, so it
	// is safe. (Real fix for throttling is the raised Bedrock quota; this only
	// keeps users from seeing a 500 during a bad window.)
	streamInput := &bedrockruntime.ConverseStreamInput{
		ModelId:         aws.String(a.modelID),
		Messages:        messages,
		System:          system,
		ToolConfig:      toolCfg,
		InferenceConfig: infCfg,
	}
	primary := a.modelID
	models := append([]string{primary}, fallbackModelIDs(primary)...)
	var out *bedrockruntime.ConverseStreamOutput
	var err error
	for _, model := range models {
		streamInput.ModelId = aws.String(model)
		for attempt := 0; attempt < 3; attempt++ {
			out, err = h.aws.Bedrock.ConverseStream(ctx, streamInput)
			if err == nil || !isTransientBedrockError(err) {
				break
			}
			select {
			case <-ctx.Done():
				err = ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 400 * time.Millisecond):
			}
		}
		if err == nil {
			break
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
	defer out.GetStream().Close()

	sendSSE(makeChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil))

	finishReason := "stop"
	var fullText string
	var inTok, outTok, cacheRead, cacheWrite int
	tcIndex := map[int32]int{} // contentBlockIndex → openai tool_call index
	var tcCounter int

	for ev := range out.GetStream().Events() {
		switch e := ev.(type) {
		case *bt.ConverseStreamOutputMemberContentBlockStart:
			if tus, ok := e.Value.Start.(*bt.ContentBlockStartMemberToolUse); ok {
				idx := tcCounter
				tcCounter++
				if e.Value.ContentBlockIndex != nil {
					tcIndex[*e.Value.ContentBlockIndex] = idx
				}
				sendSSE(makeChunk(map[string]any{
					"tool_calls": []map[string]any{{
						"index": idx, "id": aws.ToString(tus.Value.ToolUseId), "type": "function",
						"function": map[string]any{"name": aws.ToString(tus.Value.Name), "arguments": ""},
					}},
				}, nil, nil))
			}
		case *bt.ConverseStreamOutputMemberContentBlockDelta:
			switch d := e.Value.Delta.(type) {
			case *bt.ContentBlockDeltaMemberText:
				fullText += d.Value
				sendSSE(makeChunk(map[string]any{"content": d.Value}, nil, nil))
			case *bt.ContentBlockDeltaMemberToolUse:
				idx := 0
				if e.Value.ContentBlockIndex != nil {
					idx = tcIndex[*e.Value.ContentBlockIndex]
				}
				sendSSE(makeChunk(map[string]any{
					"tool_calls": []map[string]any{{
						"index":    idx,
						"function": map[string]any{"arguments": aws.ToString(d.Value.Input)},
					}},
				}, nil, nil))
			}
		case *bt.ConverseStreamOutputMemberMessageStop:
			if e.Value.StopReason == bt.StopReasonToolUse {
				finishReason = "tool_calls"
			}
		case *bt.ConverseStreamOutputMemberMetadata:
			if e.Value.Usage != nil {
				inTok = int(aws.ToInt32(e.Value.Usage.InputTokens))
				outTok = int(aws.ToInt32(e.Value.Usage.OutputTokens))
				cacheRead = int(aws.ToInt32(e.Value.Usage.CacheReadInputTokens))
				cacheWrite = int(aws.ToInt32(e.Value.Usage.CacheWriteInputTokens))
			}
		}
	}
	if serr := out.GetStream().Err(); serr != nil {
		h.logger.Error("converse stream error", "err", serr)
		finishReason = "error"
		sendSSE(map[string]any{"error": map[string]any{"code": "AI_MODEL_ERROR", "message": serr.Error()}})
	}

	usage := map[string]any{
		"prompt_tokens": inTok, "completion_tokens": outTok, "total_tokens": inTok + outTok,
	}
	if cacheRead > 0 || cacheWrite > 0 {
		usage["prompt_tokens_details"] = map[string]any{"cached_tokens": cacheRead}
		usage["cache_read_input_tokens"] = cacheRead
		usage["cache_write_input_tokens"] = cacheWrite
	}
	finishStr := finishReason
	sendSSE(makeChunk(map[string]any{}, &finishStr, usage))
	if finishReason != "error" {
		a.saveSession(fullText)
	}
	fmt.Fprintf(w, "data: [DONE]\n\n")
	if canFlush {
		flusher.Flush()
	}
}
