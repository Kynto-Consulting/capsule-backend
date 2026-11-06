package aimm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	rttypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

// Runtime is the part of the Bedrock runtime client the operations use (a fake implements it in tests).
type Runtime interface {
	InvokeModel(ctx context.Context, in *bedrockruntime.InvokeModelInput, o ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error)
	Converse(ctx context.Context, in *bedrockruntime.ConverseInput, o ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error)
	ConverseStream(ctx context.Context, in *bedrockruntime.ConverseStreamInput, o ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseStreamOutput, error)
}

// Error kinds a handler maps to HTTP statuses.
var (
	ErrBadInput    = errors.New("invalid input")
	ErrUnsupported = errors.New("unsupported for this model")
	ErrNoAccess    = errors.New("model access not granted")
)

// BadInput wraps a message as ErrBadInput.
func BadInput(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBadInput, fmt.Sprintf(format, a...))
}

// ClassifyAWS maps AWS errors to the package's kinds so callers can answer 403/422 with a clear message.
func ClassifyAWS(err error) error {
	if err == nil {
		return nil
	}
	m := err.Error()
	switch {
	case strings.Contains(m, "AccessDeniedException") || strings.Contains(m, "use case details have not been submitted") || strings.Contains(m, "not authorized") || strings.Contains(m, "don't have access to the model"):
		return fmt.Errorf("%w: %s", ErrNoAccess, shorten(m))
	case strings.Contains(m, "does not support") || strings.Contains(m, "isn't supported") || strings.Contains(m, "isn’t supported"):
		return fmt.Errorf("%w: %s", ErrUnsupported, shorten(m))
	case strings.Contains(m, "ValidationException"):
		return fmt.Errorf("%w: %s", ErrBadInput, shorten(m))
	}
	return err
}

func shorten(s string) string {
	if i := strings.Index(s, "api error "); i >= 0 {
		s = s[i+len("api error "):]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// Ops runs model calls.
type Ops struct {
	RT Runtime
}

func (o *Ops) invoke(ctx context.Context, id string, body any) ([]byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var out *bedrockruntime.InvokeModelOutput
	for attempt := 0; attempt < 3; attempt++ {
		out, err = o.RT.InvokeModel(ctx, &bedrockruntime.InvokeModelInput{ModelId: aws.String(id), Body: b, ContentType: aws.String("application/json"), Accept: aws.String("application/json")})
		if err == nil {
			return out.Body, nil
		}
		if !transient(err) {
			return nil, ClassifyAWS(err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 400 * time.Millisecond):
		}
	}
	return nil, ClassifyAWS(err)
}

func transient(err error) bool {
	m := err.Error()
	for _, s := range []string{"ThrottlingException", "ServiceUnavailable", "InternalServerException", "ModelErrorException"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

// ---- embeddings ----

// EmbedInput is one item to embed: text, an image, or both (families that accept it).
type EmbedInput struct {
	Text        string
	Image       []byte
	ImageFormat string // png|jpeg|gif|webp
}

// EmbedResult holds one vector per input and the tokens the service reported (or an estimate: chars/4).
type EmbedResult struct {
	Vectors [][]float32
	Tokens  int
	Dim     int
}

// Embed returns vectors for inputs with model m. dim 0 uses the model default (256 where the family lets you choose, to keep vectors small).
func (o *Ops) Embed(ctx context.Context, m Model, inputs []EmbedInput, dim int, purpose string) (*EmbedResult, error) {
	if len(inputs) == 0 {
		return nil, BadInput("input is empty")
	}
	if len(inputs) > 96 {
		return nil, BadInput("at most 96 inputs per call")
	}
	id := invokeID(m)
	switch m.Family {
	case FamCohereEmbed:
		var texts []string
		for _, in := range inputs {
			if len(in.Image) > 0 || in.Text == "" {
				return nil, BadInput("%s embeds text only here", m.ID)
			}
			texts = append(texts, in.Text)
		}
		if dim == 0 {
			dim = 1024
		}
		it := "search_document"
		if purpose == "query" {
			it = "search_query"
		}
		raw, err := o.invoke(ctx, id, map[string]any{"texts": texts, "input_type": it, "embedding_types": []string{"float"}, "output_dimension": dim})
		if err != nil {
			return nil, err
		}
		var r struct {
			Embeddings struct {
				Float [][]float32 `json:"float"`
			} `json:"embeddings"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || len(r.Embeddings.Float) != len(texts) {
			return nil, fmt.Errorf("unexpected embedding response from %s", m.ID)
		}
		return &EmbedResult{Vectors: r.Embeddings.Float, Tokens: estTokens(texts), Dim: len(r.Embeddings.Float[0])}, nil
	case FamTitanEmbedText, FamTitanEmbedImage, FamNovaEmbed, FamMarengoEmbed:
		res := &EmbedResult{Vectors: make([][]float32, len(inputs))}
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 4)
		var firstErr error
		for i, in := range inputs {
			wg.Add(1)
			go func(i int, in EmbedInput) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				v, tok, err := o.embedOne(ctx, m, id, in, dim, purpose)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					if firstErr == nil {
						firstErr = err
					}
					return
				}
				res.Vectors[i] = v
				res.Tokens += tok
			}(i, in)
		}
		wg.Wait()
		if firstErr != nil {
			return nil, firstErr
		}
		res.Dim = len(res.Vectors[0])
		return res, nil
	}
	return nil, fmt.Errorf("%w: %s is not an embedding model", ErrUnsupported, m.ID)
}

func (o *Ops) embedOne(ctx context.Context, m Model, id string, in EmbedInput, dim int, purpose string) ([]float32, int, error) {
	switch m.Family {
	case FamTitanEmbedText:
		if len(in.Image) > 0 || in.Text == "" {
			return nil, 0, BadInput("%s embeds text only", m.ID)
		}
		if dim == 0 {
			dim = 256
		}
		if dim != 256 && dim != 512 && dim != 1024 {
			return nil, 0, BadInput("titan text v2 dimensions: 256, 512 or 1024")
		}
		raw, err := o.invoke(ctx, id, map[string]any{"inputText": in.Text, "dimensions": dim, "normalize": true})
		if err != nil {
			return nil, 0, err
		}
		var r struct {
			Embedding []float32 `json:"embedding"`
			Tokens    int       `json:"inputTextTokenCount"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || len(r.Embedding) == 0 {
			return nil, 0, fmt.Errorf("unexpected embedding response from %s", m.ID)
		}
		return r.Embedding, r.Tokens, nil
	case FamTitanEmbedImage:
		body := map[string]any{}
		if in.Text != "" {
			body["inputText"] = in.Text
		}
		if len(in.Image) > 0 {
			body["inputImage"] = base64.StdEncoding.EncodeToString(in.Image)
		}
		if len(body) == 0 {
			return nil, 0, BadInput("empty input")
		}
		if dim == 0 {
			dim = 384
		}
		body["embeddingConfig"] = map[string]any{"outputEmbeddingLength": dim}
		raw, err := o.invoke(ctx, id, body)
		if err != nil {
			return nil, 0, err
		}
		var r struct {
			Embedding []float32 `json:"embedding"`
			Tokens    int       `json:"inputTextTokenCount"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || len(r.Embedding) == 0 {
			return nil, 0, fmt.Errorf("unexpected embedding response from %s", m.ID)
		}
		return r.Embedding, r.Tokens + imageTokens(in), nil
	case FamMarengoEmbed:
		body := map[string]any{}
		switch {
		case len(in.Image) > 0 && in.Text != "":
			return nil, 0, BadInput("marengo embeds either text or an image per item")
		case len(in.Image) > 0:
			body["inputType"] = "image"
			body["image"] = map[string]any{"mediaSource": map[string]any{"base64String": base64.StdEncoding.EncodeToString(in.Image)}}
		case in.Text != "":
			body["inputType"] = "text"
			body["text"] = map[string]any{"inputText": in.Text}
		default:
			return nil, 0, BadInput("empty input")
		}
		raw, err := o.invoke(ctx, id, body)
		if err != nil {
			return nil, 0, err
		}
		var r struct {
			Data []struct {
				Embedding []float32 `json:"embedding"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || len(r.Data) == 0 || len(r.Data[0].Embedding) == 0 {
			return nil, 0, fmt.Errorf("unexpected embedding response from %s", m.ID)
		}
		return r.Data[0].Embedding, estTokens([]string{in.Text}) + imageTokens(in), nil
	case FamNovaEmbed:
		if dim == 0 {
			dim = 256
		}
		switch dim {
		case 256, 384, 1024, 3072:
		default:
			return nil, 0, BadInput("nova embeddings dimensions: 256, 384, 1024 or 3072")
		}
		p := "GENERIC_INDEX"
		if purpose == "query" {
			p = "GENERIC_RETRIEVAL"
		}
		sp := map[string]any{"embeddingPurpose": p, "embeddingDimension": dim}
		switch {
		case len(in.Image) > 0 && in.Text != "":
			return nil, 0, BadInput("nova embeddings take either text or an image per item")
		case len(in.Image) > 0:
			sp["image"] = map[string]any{"format": in.ImageFormat, "source": map[string]any{"bytes": base64.StdEncoding.EncodeToString(in.Image)}}
		case in.Text != "":
			sp["text"] = map[string]any{"truncationMode": "END", "value": in.Text}
		default:
			return nil, 0, BadInput("empty input")
		}
		raw, err := o.invoke(ctx, id, map[string]any{"schemaVersion": "nova-multimodal-embed-v1", "taskType": "SINGLE_EMBEDDING", "singleEmbeddingParams": sp})
		if err != nil {
			return nil, 0, err
		}
		var r struct {
			Embeddings []struct {
				Embedding []float32 `json:"embedding"`
			} `json:"embeddings"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || len(r.Embeddings) == 0 || len(r.Embeddings[0].Embedding) == 0 {
			return nil, 0, fmt.Errorf("unexpected embedding response from %s", m.ID)
		}
		return r.Embeddings[0].Embedding, estTokens([]string{in.Text}) + imageTokens(in), nil
	}
	return nil, 0, ErrUnsupported
}

func imageTokens(in EmbedInput) int {
	if len(in.Image) > 0 {
		return 1000 // flat estimate: the services do not report image tokens
	}
	return 0
}

func estTokens(texts []string) int {
	n := 0
	for _, t := range texts {
		n += (len(t) + 3) / 4
	}
	return n
}

// ---- rerank ----

// RerankHit is one ranked document.
type RerankHit struct {
	Index int     `json:"index"`
	Score float64 `json:"score"`
}

// Rerank orders documents by relevance to query.
func (o *Ops) Rerank(ctx context.Context, m Model, query string, docs []string, topN int) ([]RerankHit, error) {
	if m.Family != FamCohereRerank {
		return nil, fmt.Errorf("%w: %s is not a reranking model", ErrUnsupported, m.ID)
	}
	if strings.TrimSpace(query) == "" || len(docs) == 0 {
		return nil, BadInput("query and documents are required")
	}
	if len(docs) > 1000 {
		return nil, BadInput("at most 1000 documents")
	}
	if topN <= 0 || topN > len(docs) {
		topN = len(docs)
	}
	raw, err := o.invoke(ctx, invokeID(m), map[string]any{"api_version": 2, "query": query, "documents": docs, "top_n": topN})
	if err != nil {
		return nil, err
	}
	var r struct {
		Results []struct {
			Index int     `json:"index"`
			Score float64 `json:"relevance_score"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("unexpected rerank response from %s", m.ID)
	}
	hits := make([]RerankHit, len(r.Results))
	for i, x := range r.Results {
		hits[i] = RerankHit{Index: x.Index, Score: x.Score}
	}
	return hits, nil
}

// ---- images (Stability AI services) ----

// ImageRequest drives generation and editing. Extra carries service-specific fields (search_prompt, select_prompt, style_image
// as base64, left/right/up/down, negative_prompt, seed, aspect_ratio, control_strength, fidelity, grow_mask).
type ImageRequest struct {
	Prompt string
	Image  []byte
	Mask   []byte
	N      int    // images to produce (1..4)
	Size   string // WxH of the blank canvas used for text to image (default 1024x1024)
	Format string // png|jpeg
	Extra  map[string]any
}

// Image is one produced image.
type Image struct {
	Data   []byte `json:"-"`
	Format string `json:"format"`
	Seed   int64  `json:"seed,omitempty"`
}

// stabilitySpec lists the body fields of each Stability service: required image-like and text fields.
var stabilitySpec = map[string]struct {
	needsImage, needsMask, needsPrompt bool
	extraRequired                      []string
	imageField                         string
}{
	"inpaint":              {true, true, true, nil, "image"},
	"erase-object":         {true, false, false, nil, "image"},
	"remove-background":    {true, false, false, nil, "image"},
	"search-replace":       {true, false, true, []string{"search_prompt"}, "image"},
	"search-recolor":       {true, false, true, []string{"select_prompt"}, "image"},
	"outpaint":             {true, false, false, nil, "image"},
	"style-transfer":       {true, false, false, []string{"style_image"}, "init_image"},
	"style-guide":          {true, false, true, nil, "image"},
	"fast-upscale":         {true, false, false, nil, "image"},
	"conservative-upscale": {true, false, true, nil, "image"},
	"creative-upscale":     {true, false, true, nil, "image"},
	"control-structure":    {true, false, true, nil, "image"},
	"control-sketch":       {false, false, true, nil, "image"}, // no image: blank canvas, i.e. text to image
}

// StabilityKind is the service name of a Stability model ("inpaint", "remove-background", "fast-upscale"...), the value of operation=.
func StabilityKind(m Model) string { return stabilityKind(m) }

func stabilityKind(m Model) string {
	k := strings.TrimPrefix(m.BedrockID, "stability.")
	k = strings.TrimSuffix(k, "-v1:0")
	k = strings.TrimPrefix(k, "stable-image-")
	k = strings.TrimPrefix(k, "stable-")
	return k
}

// BlankCanvas returns a white PNG of the given WxH ("1024x1024").
func BlankCanvas(size string) ([]byte, error) {
	w, h := 1024, 1024
	if size != "" {
		if _, err := fmt.Sscanf(size, "%dx%d", &w, &h); err != nil {
			return nil, BadInput("size must look like 1024x1024")
		}
	}
	if w < 64 || h < 64 || w > 2048 || h > 2048 {
		return nil, BadInput("size must be between 64x64 and 2048x2048")
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	white := color.RGBA{255, 255, 255, 255}
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = white.R, white.G, white.B, white.A
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ImageOp generates or edits images with a Stability service model.
func (o *Ops) ImageOp(ctx context.Context, m Model, req ImageRequest) ([]Image, error) {
	if m.Family != FamStability {
		return nil, fmt.Errorf("%w: %s is not an image model", ErrUnsupported, m.ID)
	}
	kind := stabilityKind(m)
	spec, ok := stabilitySpec[kind]
	if !ok {
		return nil, fmt.Errorf("%w: image service %q", ErrUnsupported, kind)
	}
	if req.N <= 0 {
		req.N = 1
	}
	if req.N > 4 {
		return nil, BadInput("at most 4 images per call")
	}
	if len(req.Prompt) > 10000 {
		return nil, BadInput("prompt is too long")
	}
	if req.Format == "" {
		req.Format = "png"
	}
	if req.Format != "png" && req.Format != "jpeg" {
		return nil, BadInput("format must be png or jpeg")
	}
	if spec.needsPrompt && strings.TrimSpace(req.Prompt) == "" {
		return nil, BadInput("%s needs a prompt", m.ID)
	}
	if spec.needsMask && len(req.Mask) == 0 {
		return nil, BadInput("%s needs a mask (white = change, black = keep)", m.ID)
	}
	img := req.Image
	if len(img) == 0 {
		if kind != "control-sketch" {
			return nil, BadInput("%s needs an input image", m.ID)
		}
		var err error
		if img, err = BlankCanvas(req.Size); err != nil {
			return nil, err
		}
	}
	for _, k := range spec.extraRequired {
		if _, ok := req.Extra[k]; !ok {
			return nil, BadInput("%s needs %q", m.ID, k)
		}
	}
	out := make([]Image, 0, req.N)
	for i := 0; i < req.N; i++ {
		body := map[string]any{spec.imageField: base64.StdEncoding.EncodeToString(img), "output_format": req.Format}
		if req.Prompt != "" {
			body["prompt"] = req.Prompt
		}
		if len(req.Mask) > 0 {
			body["mask"] = base64.StdEncoding.EncodeToString(req.Mask)
		}
		for k, v := range req.Extra {
			body[k] = v
		}
		if kind == "control-sketch" && len(req.Image) == 0 {
			if _, set := body["control_strength"]; !set {
				body["control_strength"] = 0.1 // blank sketch: let the prompt drive the picture
			}
		}
		raw, err := o.invoke(ctx, invokeID(m), body)
		if err != nil {
			return nil, err
		}
		var r struct {
			Images        []string  `json:"images"`
			Seeds         []int64   `json:"seeds"`
			FinishReasons []*string `json:"finish_reasons"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || len(r.Images) == 0 {
			return nil, fmt.Errorf("unexpected image response from %s", m.ID)
		}
		if len(r.FinishReasons) > 0 && r.FinishReasons[0] != nil {
			return nil, fmt.Errorf("%w: image refused by the model (%s)", ErrBadInput, *r.FinishReasons[0])
		}
		data, err := base64.StdEncoding.DecodeString(r.Images[0])
		if err != nil {
			return nil, fmt.Errorf("image response is not valid base64")
		}
		im := Image{Data: data, Format: req.Format}
		if len(r.Seeds) > 0 {
			im.Seed = r.Seeds[0]
		}
		out = append(out, im)
		// vary the seed between images unless the caller pinned one
		if _, pinned := req.Extra["seed"]; !pinned {
			delete(req.Extra, "seed")
		}
	}
	return out, nil
}

func invokeID(m Model) string {
	if m.InvokeID != "" {
		return m.InvokeID
	}
	return m.BedrockID
}

// ---- vision / video through Converse ----

// Attachment is a file for a chat turn.
type Attachment struct {
	Kind   string // image | video | document
	Format string // png jpeg gif webp | mp4 mov webm mkv ... | pdf txt md csv ...
	Name   string
	Data   []byte
}

// AnalyzeResult is the model's answer with the token counts.
type AnalyzeResult struct {
	Text      string
	InTokens  int
	OutTokens int
}

// AnalyzeStream is Analyze with the text delivered piece by piece to onDelta as the model writes it.
func (o *Ops) AnalyzeStream(ctx context.Context, m Model, system, prompt string, atts []Attachment, maxTokens int, onDelta func(string)) (*AnalyzeResult, error) {
	in, err := buildConverse(m, system, prompt, atts, maxTokens)
	if err != nil {
		return nil, err
	}
	out, err := o.RT.ConverseStream(ctx, &bedrockruntime.ConverseStreamInput{ModelId: in.ModelId, Messages: in.Messages, System: in.System, InferenceConfig: in.InferenceConfig})
	if err != nil {
		return nil, ClassifyAWS(err)
	}
	stream := out.GetStream()
	defer stream.Close()
	res := &AnalyzeResult{}
	for ev := range stream.Events() {
		switch v := ev.(type) {
		case *rttypes.ConverseStreamOutputMemberContentBlockDelta:
			if d, ok := v.Value.Delta.(*rttypes.ContentBlockDeltaMemberText); ok {
				res.Text += d.Value
				onDelta(d.Value)
			}
		case *rttypes.ConverseStreamOutputMemberMetadata:
			if v.Value.Usage != nil {
				res.InTokens, res.OutTokens = int(aws.ToInt32(v.Value.Usage.InputTokens)), int(aws.ToInt32(v.Value.Usage.OutputTokens))
			}
		}
	}
	if err := stream.Err(); err != nil {
		return res, ClassifyAWS(err)
	}
	return res, nil
}

func buildConverse(m Model, system, prompt string, atts []Attachment, maxTokens int) (*bedrockruntime.ConverseInput, error) {
	if m.Family != FamConverse {
		return nil, fmt.Errorf("%w: %s is not a chat model", ErrUnsupported, m.ID)
	}
	var blocks []rttypes.ContentBlock
	for i, a := range atts {
		switch a.Kind {
		case "image":
			if !m.Has(CapVision) {
				return nil, fmt.Errorf("%w: %s does not read images", ErrUnsupported, m.ID)
			}
			f := rttypes.ImageFormat(a.Format)
			switch f {
			case rttypes.ImageFormatPng, rttypes.ImageFormatJpeg, rttypes.ImageFormatGif, rttypes.ImageFormatWebp:
			default:
				return nil, BadInput("image format %q not supported (png, jpeg, gif, webp)", a.Format)
			}
			blocks = append(blocks, &rttypes.ContentBlockMemberImage{Value: rttypes.ImageBlock{Format: f, Source: &rttypes.ImageSourceMemberBytes{Value: a.Data}}})
		case "video":
			if !m.Has(CapVideo) {
				return nil, fmt.Errorf("%w: %s does not read video", ErrUnsupported, m.ID)
			}
			f := rttypes.VideoFormat(a.Format)
			switch f {
			case rttypes.VideoFormatMp4, rttypes.VideoFormatMov, rttypes.VideoFormatWebm, rttypes.VideoFormatMkv, rttypes.VideoFormatFlv, rttypes.VideoFormatMpeg, rttypes.VideoFormatMpg, rttypes.VideoFormatWmv, rttypes.VideoFormatThreeGp:
			default:
				return nil, BadInput("video format %q not supported", a.Format)
			}
			blocks = append(blocks, &rttypes.ContentBlockMemberVideo{Value: rttypes.VideoBlock{Format: f, Source: &rttypes.VideoSourceMemberBytes{Value: a.Data}}})
		case "document":
			name := a.Name
			if name == "" {
				name = fmt.Sprintf("document-%d", i+1)
			}
			blocks = append(blocks, &rttypes.ContentBlockMemberDocument{Value: rttypes.DocumentBlock{Format: rttypes.DocumentFormat(a.Format), Name: aws.String(sanitizeDocName(name)), Source: &rttypes.DocumentSourceMemberBytes{Value: a.Data}}})
		default:
			return nil, BadInput("attachment kind %q not supported", a.Kind)
		}
	}
	blocks = append(blocks, &rttypes.ContentBlockMemberText{Value: prompt})
	in := &bedrockruntime.ConverseInput{
		ModelId:         aws.String(invokeID(m)),
		Messages:        []rttypes.Message{{Role: rttypes.ConversationRoleUser, Content: blocks}},
		InferenceConfig: &rttypes.InferenceConfiguration{MaxTokens: aws.Int32(int32(maxTokens))},
	}
	if system != "" {
		in.System = []rttypes.SystemContentBlock{&rttypes.SystemContentBlockMemberText{Value: system}}
	}
	return in, nil
}

// Analyze sends prompt plus attachments to a Converse model and waits for the whole answer.
func (o *Ops) Analyze(ctx context.Context, m Model, system, prompt string, atts []Attachment, maxTokens int) (*AnalyzeResult, error) {
	in, err := buildConverse(m, system, prompt, atts, maxTokens)
	if err != nil {
		return nil, err
	}
	var out *bedrockruntime.ConverseOutput
	for attempt := 0; attempt < 3; attempt++ {
		out, err = o.RT.Converse(ctx, in)
		if err == nil || !transient(err) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 400 * time.Millisecond):
		}
	}
	if err != nil {
		return nil, ClassifyAWS(err)
	}
	res := &AnalyzeResult{}
	if msg, ok := out.Output.(*rttypes.ConverseOutputMemberMessage); ok {
		for _, c := range msg.Value.Content {
			if t, ok := c.(*rttypes.ContentBlockMemberText); ok {
				res.Text += t.Value
			}
		}
	}
	if out.Usage != nil {
		res.InTokens, res.OutTokens = int(aws.ToInt32(out.Usage.InputTokens)), int(aws.ToInt32(out.Usage.OutputTokens))
	}
	return res, nil
}

// sanitizeDocName keeps what Converse accepts in document names: alphanumerics, spaces, hyphens, brackets.
func sanitizeDocName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ', r == '-', r == '(', r == ')', r == '[', r == ']':
			b.WriteRune(r)
		default:
			b.WriteRune(' ')
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
