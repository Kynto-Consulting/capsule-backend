// Package aimm is Capsule's multimodal AI layer on top of AWS Bedrock, Amazon Transcribe and Amazon Polly:
// a model catalog grouped by capability, the request/response formats of each model family, price estimates
// and per-project quotas. It has no HTTP code; handlers/aimm.go exposes it.
package aimm

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
)

// Capability is what a model can do for a caller.
type Capability string

const (
	CapChat           Capability = "chat"
	CapVision         Capability = "vision"
	CapSTT            Capability = "stt"
	CapTTS            Capability = "tts"
	CapSpeechToSpeech Capability = "speech-to-speech"
	CapImageGenerate  Capability = "image-generate"
	CapImageEdit      Capability = "image-edit"
	CapEmbed          Capability = "embed"
	CapRerank         Capability = "rerank"
	CapVideo          Capability = "video"
)

// AllCapabilities lists every capability in display order.
var AllCapabilities = []Capability{CapChat, CapVision, CapSTT, CapTTS, CapSpeechToSpeech, CapImageGenerate, CapImageEdit, CapEmbed, CapRerank, CapVideo}

// Valid reports whether c is a known capability.
func (c Capability) Valid() bool {
	for _, k := range AllCapabilities {
		if k == c {
			return true
		}
	}
	return false
}

// Service is the AWS API that serves a model.
type Service string

const (
	SvcBedrock    Service = "bedrock"
	SvcTranscribe Service = "transcribe"
	SvcPolly      Service = "polly"
)

// Family names the request/response format driver of a model.
type Family string

const (
	FamTitanEmbedText  Family = "titan-embed-text"
	FamTitanEmbedImage Family = "titan-embed-image"
	FamNovaEmbed       Family = "nova-embed"
	FamCohereEmbed     Family = "cohere-embed"
	FamMarengoEmbed    Family = "marengo-embed"
	FamCohereRerank    Family = "cohere-rerank"
	FamStability       Family = "stability-image"
	FamNovaSonic       Family = "nova-sonic"
	FamConverse        Family = "converse"
	FamTranscribe      Family = "transcribe"
	FamPolly           Family = "polly"
)

// Price is an estimate in US dollars; Unit says what the numbers count ("1k_tokens", "image", "minute", "1m_chars", "1k_searches").
type Price struct {
	Unit   string  `json:"unit"`
	Input  float64 `json:"input,omitempty"`
	Output float64 `json:"output,omitempty"`
	Per    float64 `json:"per,omitempty"` // flat price per Unit
}

// Model is one catalog entry.
type Model struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	Provider         string       `json:"provider"`
	Service          Service      `json:"service"`
	Family           Family       `json:"family"`
	BedrockID        string       `json:"bedrock_id,omitempty"`
	InvokeID         string       `json:"invoke_id,omitempty"` // id actually called: the regional inference profile when the model has no on-demand mode
	Capabilities     []Capability `json:"capabilities"`
	InputModalities  []string     `json:"input_modalities,omitempty"`
	OutputModalities []string     `json:"output_modalities,omitempty"`
	Streaming        bool         `json:"streaming,omitempty"`
	Price            Price        `json:"price"`
	Available        bool         `json:"available"`
	Reason           string       `json:"reason,omitempty"` // why it is not available, or a note about its state
	Source           string       `json:"source"`           // live | fallback
	Verified         bool         `json:"verified"`         // request/response format exercised against the real service
	Note             string       `json:"note,omitempty"`
}

// Has reports whether m offers capability c.
func (m Model) Has(c Capability) bool {
	for _, k := range m.Capabilities {
		if k == c {
			return true
		}
	}
	return false
}

// CapabilityInfo says whether a capability has at least one usable model, and why not when it does not.
type CapabilityInfo struct {
	ID        Capability `json:"id"`
	Available bool       `json:"available"`
	Models    int        `json:"models"`
	Reason    string     `json:"reason,omitempty"`
}

// driver is a model Capsule knows how to call. Everything else Bedrock lists is offered only as chat when it takes text.
type driver struct {
	bedrockID string
	id        string
	name      string
	provider  string
	family    Family
	caps      []Capability
	price     Price
	verified  bool
	note      string
	streaming bool
}

func stab(id, name string, price float64, verified bool, caps ...Capability) driver {
	short := strings.TrimSuffix(strings.TrimPrefix(id, "stable-"), "-v1:0")
	return driver{bedrockID: "stability." + id, id: "stability-" + short, name: name, provider: "Stability AI",
		family: FamStability, caps: caps, price: Price{Unit: "image", Per: price}, verified: verified}
}

var drivers = []driver{
	{bedrockID: "amazon.titan-embed-text-v2:0", id: "titan-embed-v2", name: "Titan Text Embeddings V2", provider: "Amazon", family: FamTitanEmbedText, caps: []Capability{CapEmbed}, price: Price{Unit: "1k_tokens", Input: 0.00002}, verified: true},
	{bedrockID: "amazon.titan-embed-image-v1", id: "titan-embed-image", name: "Titan Multimodal Embeddings G1", provider: "Amazon", family: FamTitanEmbedImage, caps: []Capability{CapEmbed}, price: Price{Unit: "1k_tokens", Input: 0.0008}, note: "text and image into one vector space"},
	{bedrockID: "amazon.nova-2-multimodal-embeddings-v1:0", id: "nova-embed", name: "Nova 2 Multimodal Embeddings", provider: "Amazon", family: FamNovaEmbed, caps: []Capability{CapEmbed}, price: Price{Unit: "1k_tokens", Input: 0.00014}, verified: true, note: "text and image (audio and video need the asynchronous API)"},
	{bedrockID: "cohere.embed-v4:0", id: "cohere-embed-v4", name: "Cohere Embed v4", provider: "Cohere", family: FamCohereEmbed, caps: []Capability{CapEmbed}, price: Price{Unit: "1k_tokens", Input: 0.00012}, verified: true},
	{bedrockID: "twelvelabs.marengo-embed-3-0-v1:0", id: "marengo-embed-3", name: "TwelveLabs Marengo Embed 3", provider: "TwelveLabs", family: FamMarengoEmbed, caps: []Capability{CapEmbed}, price: Price{Unit: "1k_tokens", Input: 0.00007}, verified: true, note: "text and image, 512 dimensions (video and audio need the asynchronous API)"},
	{bedrockID: "cohere.rerank-v3-5:0", id: "cohere-rerank-3-5", name: "Cohere Rerank 3.5", provider: "Cohere", family: FamCohereRerank, caps: []Capability{CapRerank}, price: Price{Unit: "1k_searches", Per: 2.0}, verified: true},
	stab("stable-image-inpaint-v1:0", "Stable Image Inpaint", 0.04, true, CapImageEdit),
	stab("stable-image-erase-object-v1:0", "Stable Image Erase Object", 0.04, false, CapImageEdit),
	stab("stable-image-remove-background-v1:0", "Stable Image Remove Background", 0.07, true, CapImageEdit),
	stab("stable-image-search-replace-v1:0", "Stable Image Search and Replace", 0.04, false, CapImageEdit),
	stab("stable-image-search-recolor-v1:0", "Stable Image Search and Recolor", 0.04, false, CapImageEdit),
	stab("stable-outpaint-v1:0", "Stable Outpaint", 0.04, false, CapImageEdit),
	stab("stable-style-transfer-v1:0", "Stable Style Transfer", 0.08, false, CapImageEdit),
	stab("stable-image-style-guide-v1:0", "Stable Image Style Guide", 0.07, true, CapImageEdit),
	stab("stable-fast-upscale-v1:0", "Stable Fast Upscale", 0.01, false, CapImageEdit),
	stab("stable-conservative-upscale-v1:0", "Stable Conservative Upscale", 0.40, false, CapImageEdit),
	stab("stable-creative-upscale-v1:0", "Stable Creative Upscale", 0.60, false, CapImageEdit),
	stab("stable-image-control-structure-v1:0", "Stable Image Control Structure", 0.07, false, CapImageEdit),
	func() driver {
		d := stab("stable-image-control-sketch-v1:0", "Stable Image Control Sketch", 0.07, true, CapImageGenerate, CapImageEdit)
		d.note = "text to image: with no input image Capsule sends a blank canvas as the sketch (the account has no dedicated text-to-image model)"
		return d
	}(),
	{bedrockID: "amazon.nova-2-sonic-v1:0", id: "nova-2-sonic", name: "Nova 2 Sonic", provider: "Amazon", family: FamNovaSonic, caps: []Capability{CapSpeechToSpeech}, price: Price{Unit: "minute", Per: 0.06}, streaming: true},
	{bedrockID: "amazon.nova-2-5-sonic", id: "nova-2-5-sonic", name: "Nova 2.5 Sonic", provider: "Amazon", family: FamNovaSonic, caps: []Capability{CapSpeechToSpeech}, price: Price{Unit: "minute", Per: 0.06}, streaming: true},
	{bedrockID: "mistral.voxtral-mini-3b-2507", id: "voxtral-mini", name: "Voxtral Mini 3B", provider: "Mistral AI", family: FamConverse, caps: []Capability{CapChat}, price: Price{Unit: "1k_tokens", Input: 0.00004, Output: 0.00004}, streaming: true,
		note: "listed with speech input, but Bedrock rejects audio ('Model does not support audio modality', checked 2026-11-05): use Amazon Transcribe for speech to text"},
	{bedrockID: "mistral.voxtral-small-24b-2507", id: "voxtral-small", name: "Voxtral Small 24B", provider: "Mistral AI", family: FamConverse, caps: []Capability{CapChat}, price: Price{Unit: "1k_tokens", Input: 0.0001, Output: 0.0003}, streaming: true,
		note: "listed with speech input, but Bedrock rejects audio (checked 2026-11-05): use Amazon Transcribe for speech to text"},
	{bedrockID: "amazon.nova-2-lite-v1:0", id: "nova-2-lite", name: "Nova 2 Lite", provider: "Amazon", family: FamConverse, caps: []Capability{CapChat, CapVision, CapVideo}, price: Price{Unit: "1k_tokens", Input: 0.0003, Output: 0.0025}, verified: true, streaming: true},
	{bedrockID: "amazon.nova-pro-v1:0", id: "nova-pro", name: "Nova Pro", provider: "Amazon", family: FamConverse, caps: []Capability{CapChat, CapVision, CapVideo}, price: Price{Unit: "1k_tokens", Input: 0.0008, Output: 0.0032}, streaming: true},
	{bedrockID: "amazon.nova-lite-v1:0", id: "nova-lite", name: "Nova Lite", provider: "Amazon", family: FamConverse, caps: []Capability{CapChat, CapVision, CapVideo}, price: Price{Unit: "1k_tokens", Input: 0.00006, Output: 0.00024}, streaming: true},
	{bedrockID: "anthropic.claude-haiku-4-5-20251001-v1:0", id: "claude-haiku-4.5", name: "Claude Haiku 4.5", provider: "Anthropic", family: FamConverse, caps: []Capability{CapChat, CapVision}, price: Price{Unit: "1k_tokens", Input: 0.001, Output: 0.005}, verified: true, streaming: true},
	{bedrockID: "anthropic.claude-sonnet-4-5-20250929-v1:0", id: "claude-sonnet-4.5", name: "Claude Sonnet 4.5", provider: "Anthropic", family: FamConverse, caps: []Capability{CapChat, CapVision}, price: Price{Unit: "1k_tokens", Input: 0.003, Output: 0.015}, streaming: true},
	{bedrockID: "anthropic.claude-opus-4-5-20251101-v1:0", id: "claude-opus-4.5", name: "Claude Opus 4.5", provider: "Anthropic", family: FamConverse, caps: []Capability{CapChat, CapVision}, price: Price{Unit: "1k_tokens", Input: 0.005, Output: 0.025}, streaming: true},
}

// Non-Bedrock providers of the same catalog.
var serviceModels = []Model{
	{ID: "transcribe", Name: "Amazon Transcribe", Provider: "Amazon", Service: SvcTranscribe, Family: FamTranscribe, Capabilities: []Capability{CapSTT},
		InputModalities: []string{"AUDIO"}, OutputModalities: []string{"TEXT"}, Price: Price{Unit: "minute", Per: 0.024}, Verified: true,
		Note: "batch jobs with speaker labels (--diarize) and timestamps; asynchronous"},
	{ID: "polly-neural", Name: "Amazon Polly (neural)", Provider: "Amazon", Service: SvcPolly, Family: FamPolly, Capabilities: []Capability{CapTTS},
		InputModalities: []string{"TEXT"}, OutputModalities: []string{"AUDIO"}, Price: Price{Unit: "1m_chars", Per: 16.0}, Verified: true},
	{ID: "polly-generative", Name: "Amazon Polly (generative)", Provider: "Amazon", Service: SvcPolly, Family: FamPolly, Capabilities: []Capability{CapTTS},
		InputModalities: []string{"TEXT"}, OutputModalities: []string{"AUDIO"}, Price: Price{Unit: "1m_chars", Per: 30.0}},
	{ID: "polly-standard", Name: "Amazon Polly (standard)", Provider: "Amazon", Service: SvcPolly, Family: FamPolly, Capabilities: []Capability{CapTTS},
		InputModalities: []string{"TEXT"}, OutputModalities: []string{"AUDIO"}, Price: Price{Unit: "1m_chars", Per: 4.0}},
}

// BedrockControl is the part of the Bedrock control-plane client the catalog needs.
type BedrockControl interface {
	ListFoundationModels(ctx context.Context, in *bedrock.ListFoundationModelsInput, o ...func(*bedrock.Options)) (*bedrock.ListFoundationModelsOutput, error)
	GetFoundationModelAvailability(ctx context.Context, in *bedrock.GetFoundationModelAvailabilityInput, o ...func(*bedrock.Options)) (*bedrock.GetFoundationModelAvailabilityOutput, error)
	ListInferenceProfiles(ctx context.Context, in *bedrock.ListInferenceProfilesInput, o ...func(*bedrock.Options)) (*bedrock.ListInferenceProfilesOutput, error)
}

// Catalog builds and caches the model list.
type Catalog struct {
	ctl    BedrockControl // nil: fixed fallback only
	region string
	ttl    time.Duration
	now    func() time.Time

	mu     sync.Mutex
	cached []Model
	at     time.Time
	live   bool
}

// NewCatalog returns a catalog over ctl (may be nil) for region.
func NewCatalog(ctl BedrockControl, region string) *Catalog {
	if region == "" {
		region = "us-east-1"
	}
	return &Catalog{ctl: ctl, region: region, ttl: 15 * time.Minute, now: time.Now}
}

// profilePrefix is the cross-region inference profile prefix of a region.
func profilePrefix(region string) string {
	switch {
	case strings.HasPrefix(region, "eu-"):
		return "eu"
	case strings.HasPrefix(region, "ap-"):
		return "apac"
	default:
		return "us"
	}
}

// Models returns the catalog, refreshed from Bedrock when the cache is older than the ttl; when Bedrock cannot be reached
// it returns the fixed list (Source "fallback") instead of failing.
func (c *Catalog) Models(ctx context.Context) []Model {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached != nil && c.now().Sub(c.at) < c.ttl {
		return c.cached
	}
	var ms []Model
	if c.ctl != nil {
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		ms = c.build(cctx)
		cancel()
	}
	if ms == nil {
		ms = c.fallback()
		c.live = false
		// short life, so the next call tries Bedrock again
		c.cached, c.at = ms, c.now().Add(-c.ttl+30*time.Second)
		return ms
	}
	c.live = true
	c.cached, c.at = ms, c.now()
	return ms
}

// Live reports whether the last build came from the Bedrock API.
func (c *Catalog) Live() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.live }

// Get returns the model with that id (the alias or the Bedrock id).
func (c *Catalog) Get(ctx context.Context, id string) (Model, bool) {
	for _, m := range c.Models(ctx) {
		if m.ID == id || m.BedrockID == id || (m.InvokeID != "" && m.InvokeID == id) {
			return m, true
		}
	}
	return Model{}, false
}

// ByCapability filters the catalog; availableOnly drops the unusable ones.
func (c *Catalog) ByCapability(ctx context.Context, cap Capability, availableOnly bool) []Model {
	var out []Model
	for _, m := range c.Models(ctx) {
		if cap != "" && !m.Has(cap) {
			continue
		}
		if availableOnly && !m.Available {
			continue
		}
		out = append(out, m)
	}
	return out
}

// Capabilities summarizes every capability with its reason when empty.
func (c *Catalog) Capabilities(ctx context.Context) []CapabilityInfo {
	ms := c.Models(ctx)
	out := make([]CapabilityInfo, 0, len(AllCapabilities))
	for _, cap := range AllCapabilities {
		info := CapabilityInfo{ID: cap}
		total := 0
		var reasons []string
		for _, m := range ms {
			if !m.Has(cap) {
				continue
			}
			total++
			if m.Available {
				info.Models++
			} else if m.Reason != "" {
				reasons = append(reasons, m.ID+": "+m.Reason)
			}
		}
		info.Available = info.Models > 0
		if !info.Available {
			if total == 0 {
				info.Reason = "no model with this capability exists in the account's catalog for " + c.region
			} else {
				info.Reason = strings.Join(reasons, "; ")
			}
		}
		out = append(out, info)
	}
	return out
}

func (c *Catalog) fallback() []Model {
	var ms []Model
	for _, d := range drivers {
		m := d.model("fallback")
		m.Available = true
		m.Reason = "catalog offline: availability not checked"
		m.InvokeID = m.BedrockID
		if needsProfile(m.BedrockID) {
			m.InvokeID = profilePrefix(c.region) + "." + m.BedrockID
		}
		ms = append(ms, m)
	}
	for _, m := range serviceModels {
		m.Source, m.Available = "fallback", true
		ms = append(ms, m)
	}
	return ms
}

// needsProfile is the fixed knowledge of which known ids have no on-demand mode (used only by the fallback).
func needsProfile(id string) bool {
	return strings.HasPrefix(id, "stability.") || strings.HasPrefix(id, "twelvelabs.marengo") || id == "amazon.nova-2-lite-v1:0" || strings.HasPrefix(id, "anthropic.claude-")
}

func (d driver) model(source string) Model {
	return Model{ID: d.id, Name: d.name, Provider: d.provider, Service: SvcBedrock, Family: d.family, BedrockID: d.bedrockID,
		Capabilities: d.caps, Streaming: d.streaming, Price: d.price, Source: source, Verified: d.verified, Note: d.note}
}

func (c *Catalog) build(ctx context.Context) []Model {
	lm, err := c.ctl.ListFoundationModels(ctx, &bedrock.ListFoundationModelsInput{})
	if err != nil || lm == nil || len(lm.ModelSummaries) == 0 {
		return nil
	}
	byID := map[string]bedrocktypes.FoundationModelSummary{}
	for _, s := range lm.ModelSummaries {
		byID[aws.ToString(s.ModelId)] = s
	}
	profiles := map[string]bool{}
	if pr, err := c.ctl.ListInferenceProfiles(ctx, &bedrock.ListInferenceProfilesInput{MaxResults: aws.Int32(1000)}); err == nil && pr != nil {
		for _, p := range pr.InferenceProfileSummaries {
			profiles[aws.ToString(p.InferenceProfileId)] = true
		}
	}

	// Availability of the known models, in parallel.
	type avail struct{ auth, entitlement, region string }
	res := make([]avail, len(drivers))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, d := range drivers {
		if _, ok := byID[d.bedrockID]; !ok {
			continue
		}
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			o, err := c.ctl.GetFoundationModelAvailability(ctx, &bedrock.GetFoundationModelAvailabilityInput{ModelId: aws.String(id)})
			if err != nil || o == nil {
				res[i] = avail{auth: "UNKNOWN"}
				return
			}
			res[i] = avail{auth: string(o.AuthorizationStatus), entitlement: string(o.EntitlementAvailability), region: string(o.RegionAvailability)}
		}(i, d.bedrockID)
	}
	wg.Wait()

	var ms []Model
	known := map[string]bool{}
	for i, d := range drivers {
		known[d.bedrockID] = true
		m := d.model("live")
		s, ok := byID[d.bedrockID]
		if !ok {
			m.Available, m.Reason = false, "model not offered in "+c.region
			ms = append(ms, m)
			continue
		}
		m.InputModalities, m.OutputModalities = modalities(s)
		c.resolveInvoke(&m, s, profiles)
		a := res[i]
		switch {
		case a.region != "" && a.region != "AVAILABLE":
			m.Available, m.Reason = false, "not available in "+c.region
		case a.auth == "UNKNOWN":
			m.Available, m.Reason = true, "access not checked (availability API unreachable)"
		case a.auth != "AUTHORIZED":
			m.Available, m.Reason = false, "access not granted: enable the model in the AWS console (Bedrock > Model access)"
		case a.entitlement != "" && a.entitlement != "AVAILABLE":
			m.Available, m.Reason = false, "account is not entitled to the model ("+strings.ToLower(a.entitlement)+")"
		case m.InvokeID == "":
			m.Available, m.Reason = false, "no on-demand mode and no inference profile in this region"
		default:
			m.Available = true
		}
		if l := s.ModelLifecycle; l != nil && l.Status == bedrocktypes.FoundationModelLifecycleStatusLegacy && m.Available {
			m.Reason = "legacy model: AWS plans to retire it"
		}
		ms = append(ms, m)
	}
	// Every other text model Bedrock lists is plain chat through Converse, available when it can be called.
	var rest []string
	for id := range byID {
		if !known[id] {
			rest = append(rest, id)
		}
	}
	sort.Strings(rest)
	for _, id := range rest {
		s := byID[id]
		in, out := modalities(s)
		if len(out) != 1 || out[0] != "TEXT" || strings.Count(id, ":") > 1 {
			continue
		}
		if s.ModelLifecycle != nil && s.ModelLifecycle.Status == bedrocktypes.FoundationModelLifecycleStatusLegacy {
			continue
		}
		m := Model{ID: id, Name: aws.ToString(s.ModelName), Provider: aws.ToString(s.ProviderName), Service: SvcBedrock, Family: FamConverse, BedrockID: id,
			Capabilities: []Capability{CapChat}, InputModalities: in, OutputModalities: out, Streaming: aws.ToBool(s.ResponseStreamingSupported),
			Price: Price{Unit: "1k_tokens"}, Source: "live", Note: "price not in the table: the cost estimate reports tokens only"}
		if contains(in, "IMAGE") {
			m.Capabilities = append(m.Capabilities, CapVision)
		}
		c.resolveInvoke(&m, s, profiles)
		if m.InvokeID == "" {
			continue
		}
		m.Available = true
		m.Reason = "access not checked for this model"
		ms = append(ms, m)
	}
	for _, m := range serviceModels {
		m.Source, m.Available = "live", true
		ms = append(ms, m)
	}
	return ms
}

func modalities(s bedrocktypes.FoundationModelSummary) (in, out []string) {
	for _, m := range s.InputModalities {
		in = append(in, string(m))
	}
	for _, m := range s.OutputModalities {
		out = append(out, string(m))
	}
	return
}

// resolveInvoke picks the id to call: the base id when on-demand works, else the regional inference profile.
func (c *Catalog) resolveInvoke(m *Model, s bedrocktypes.FoundationModelSummary, profiles map[string]bool) {
	for _, t := range s.InferenceTypesSupported {
		if t == bedrocktypes.InferenceTypeOnDemand {
			m.InvokeID = m.BedrockID
			return
		}
	}
	for _, p := range []string{profilePrefix(c.region), "global"} {
		if id := p + "." + m.BedrockID; profiles[id] {
			m.InvokeID = id
			return
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
