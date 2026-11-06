package aimm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	rttypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/aws-sdk-go-v2/service/polly"
	pollytypes "github.com/aws/aws-sdk-go-v2/service/polly/types"
	"github.com/aws/aws-sdk-go-v2/service/transcribe"
	trtypes "github.com/aws/aws-sdk-go-v2/service/transcribe/types"
)

// ---- fakes ----

type fakeRT struct {
	gotModel string
	gotBody  map[string]any
	reply    string
	err      error
	calls    int
	conv     *bedrockruntime.ConverseInput
}

func (f *fakeRT) InvokeModel(_ context.Context, in *bedrockruntime.InvokeModelInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error) {
	f.calls++
	f.gotModel = aws.ToString(in.ModelId)
	f.gotBody = map[string]any{}
	_ = json.Unmarshal(in.Body, &f.gotBody)
	if f.err != nil {
		return nil, f.err
	}
	return &bedrockruntime.InvokeModelOutput{Body: []byte(f.reply)}, nil
}

func (f *fakeRT) Converse(_ context.Context, in *bedrockruntime.ConverseInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	f.conv = in
	if f.err != nil {
		return nil, f.err
	}
	return &bedrockruntime.ConverseOutput{
		Output: &rttypes.ConverseOutputMemberMessage{Value: rttypes.Message{Role: rttypes.ConversationRoleAssistant, Content: []rttypes.ContentBlock{&rttypes.ContentBlockMemberText{Value: "una manzana"}}}},
		Usage:  &rttypes.TokenUsage{InputTokens: aws.Int32(300), OutputTokens: aws.Int32(4)},
	}, nil
}

func (f *fakeRT) ConverseStream(context.Context, *bedrockruntime.ConverseStreamInput, ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseStreamOutput, error) {
	return nil, errors.New("not used")
}

func model(id string) Model {
	for _, d := range drivers {
		if d.id == id {
			m := d.model("live")
			m.Available, m.InvokeID = true, d.bedrockID
			if needsProfile(d.bedrockID) {
				m.InvokeID = "us." + d.bedrockID
			}
			return m
		}
	}
	for _, m := range serviceModels {
		if m.ID == id {
			m.Available = true
			return m
		}
	}
	panic("no model " + id)
}

// ---- catalog ----

type fakeCtl struct {
	models   []bedrocktypes.FoundationModelSummary
	auth     map[string]bedrocktypes.AuthorizationStatus
	profiles []string
	failList bool
}

func (c *fakeCtl) ListFoundationModels(context.Context, *bedrock.ListFoundationModelsInput, ...func(*bedrock.Options)) (*bedrock.ListFoundationModelsOutput, error) {
	if c.failList {
		return nil, errors.New("down")
	}
	return &bedrock.ListFoundationModelsOutput{ModelSummaries: c.models}, nil
}

func (c *fakeCtl) GetFoundationModelAvailability(_ context.Context, in *bedrock.GetFoundationModelAvailabilityInput, _ ...func(*bedrock.Options)) (*bedrock.GetFoundationModelAvailabilityOutput, error) {
	a, ok := c.auth[aws.ToString(in.ModelId)]
	if !ok {
		a = bedrocktypes.AuthorizationStatusAuthorized
	}
	return &bedrock.GetFoundationModelAvailabilityOutput{AuthorizationStatus: a, EntitlementAvailability: bedrocktypes.EntitlementAvailabilityAvailable, RegionAvailability: bedrocktypes.RegionAvailabilityAvailable}, nil
}

func (c *fakeCtl) ListInferenceProfiles(context.Context, *bedrock.ListInferenceProfilesInput, ...func(*bedrock.Options)) (*bedrock.ListInferenceProfilesOutput, error) {
	out := &bedrock.ListInferenceProfilesOutput{}
	for _, p := range c.profiles {
		out.InferenceProfileSummaries = append(out.InferenceProfileSummaries, bedrocktypes.InferenceProfileSummary{InferenceProfileId: aws.String(p)})
	}
	return out, nil
}

func summary(id string, in, out []bedrocktypes.ModelModality, types ...bedrocktypes.InferenceType) bedrocktypes.FoundationModelSummary {
	return bedrocktypes.FoundationModelSummary{ModelId: aws.String(id), ModelName: aws.String(id), ProviderName: aws.String("x"), InputModalities: in, OutputModalities: out, InferenceTypesSupported: types}
}

func TestCatalogLiveFromBedrock(t *testing.T) {
	txt, img := bedrocktypes.ModelModalityText, bedrocktypes.ModelModalityImage
	od, prof := bedrocktypes.InferenceTypeOnDemand, bedrocktypes.InferenceType("INFERENCE_PROFILE")
	ctl := &fakeCtl{
		models: []bedrocktypes.FoundationModelSummary{
			summary("amazon.titan-embed-text-v2:0", []bedrocktypes.ModelModality{txt}, []bedrocktypes.ModelModality{bedrocktypes.ModelModalityEmbedding}, od),
			summary("stability.stable-image-inpaint-v1:0", []bedrocktypes.ModelModality{txt, img}, []bedrocktypes.ModelModality{img}, prof),
			summary("cohere.rerank-v3-5:0", []bedrocktypes.ModelModality{txt}, []bedrocktypes.ModelModality{txt}, od),
			summary("mistral.voxtral-mini-3b-2507", []bedrocktypes.ModelModality{bedrocktypes.ModelModality("SPEECH"), txt}, []bedrocktypes.ModelModality{txt}, od),
			summary("acme.new-chat-v1:0", []bedrocktypes.ModelModality{txt, img}, []bedrocktypes.ModelModality{txt}, od),
		},
		auth:     map[string]bedrocktypes.AuthorizationStatus{"cohere.rerank-v3-5:0": bedrocktypes.AuthorizationStatusNotAuthorized},
		profiles: []string{"us.stability.stable-image-inpaint-v1:0"},
	}
	c := NewCatalog(ctl, "us-east-1")
	ctx := context.Background()
	if len(c.Models(ctx)) == 0 || !c.Live() {
		t.Fatal("expected a live catalog")
	}
	inp, ok := c.Get(ctx, "stability-image-inpaint")
	if !ok || !inp.Available || inp.InvokeID != "us.stability.stable-image-inpaint-v1:0" {
		t.Fatalf("inpaint should call the regional profile: %+v", inp)
	}
	rr, _ := c.Get(ctx, "cohere-rerank-3-5")
	if rr.Available || !strings.Contains(rr.Reason, "access not granted") {
		t.Fatalf("not authorized model must say why: %+v", rr)
	}
	vx, _ := c.Get(ctx, "voxtral-mini")
	if !vx.Has(CapChat) || vx.Has(CapSTT) || !strings.Contains(vx.Note, "rejects audio") {
		t.Fatalf("voxtral is chat only, with the audio note: %+v", vx)
	}
	other, ok := c.Get(ctx, "acme.new-chat-v1:0")
	if !ok || !other.Has(CapVision) || !other.Available {
		t.Fatalf("unknown text models are offered as chat/vision: %+v", other)
	}
	if m, _ := c.Get(ctx, "nova-embed"); m.Available || !strings.Contains(m.Reason, "not offered") {
		t.Fatalf("missing model must be unavailable: %+v", m)
	}
	var capsOK = map[Capability]bool{}
	for _, ci := range c.Capabilities(ctx) {
		capsOK[ci.ID] = ci.Available
		if ci.ID == CapRerank && ci.Available {
			t.Error("rerank has no authorized model")
		}
		if ci.ID == CapSpeechToSpeech && ci.Available || ci.ID == CapSpeechToSpeech && ci.Reason == "" {
			t.Errorf("speech-to-speech should be unavailable with a reason: %+v", ci)
		}
	}
	if !capsOK[CapEmbed] || !capsOK[CapImageEdit] || !capsOK[CapSTT] || !capsOK[CapTTS] {
		t.Errorf("capabilities: %v", capsOK)
	}
	if len(c.ByCapability(ctx, CapTTS, true)) != 3 {
		t.Error("polly engines belong to tts")
	}
}

func TestCatalogFallbackWhenBedrockIsDown(t *testing.T) {
	c := NewCatalog(&fakeCtl{failList: true}, "us-east-1")
	ms := c.Models(context.Background())
	if c.Live() || len(ms) == 0 {
		t.Fatal("expected the fixed fallback")
	}
	for _, m := range ms {
		if m.Source != "fallback" {
			t.Fatalf("%s source %s", m.ID, m.Source)
		}
	}
	m, _ := c.Get(context.Background(), "stability-image-inpaint")
	if m.InvokeID != "us.stability.stable-image-inpaint-v1:0" {
		t.Errorf("fallback must use the regional profile: %q", m.InvokeID)
	}
	if NewCatalog(nil, "eu-west-1").fallback()[len(drivers)-1].BedrockID == "" {
		t.Error("nil control plane still gives the fallback")
	}
	if eu, _ := NewCatalog(nil, "eu-west-1").Get(context.Background(), "stability-image-inpaint"); eu.InvokeID != "eu.stability.stable-image-inpaint-v1:0" {
		t.Errorf("profile prefix of eu: %q", eu.InvokeID)
	}
}

// ---- embeddings ----

func TestEmbedFormats(t *testing.T) {
	ctx := context.Background()
	rt := &fakeRT{reply: `{"embedding":[0.1,0.2],"inputTextTokenCount":7}`}
	o := &Ops{RT: rt}
	r, err := o.Embed(ctx, model("titan-embed-v2"), []EmbedInput{{Text: "hola"}}, 0, "")
	if err != nil || r.Dim != 2 || r.Tokens != 7 {
		t.Fatalf("titan: %v %+v", err, r)
	}
	if rt.gotModel != "amazon.titan-embed-text-v2:0" || rt.gotBody["inputText"] != "hola" || rt.gotBody["dimensions"].(float64) != 256 || rt.gotBody["normalize"] != true {
		t.Fatalf("titan request: %v %v", rt.gotModel, rt.gotBody)
	}
	if _, err := o.Embed(ctx, model("titan-embed-v2"), []EmbedInput{{Text: "x"}}, 300, ""); !errors.Is(err, ErrBadInput) {
		t.Errorf("bad dimensions must be rejected: %v", err)
	}

	rt.reply = `{"embeddings":[{"embeddingType":"TEXT","embedding":[0.5,0.6,0.7]}]}`
	if r, err = o.Embed(ctx, model("nova-embed"), []EmbedInput{{Text: "hola"}}, 256, "query"); err != nil || r.Dim != 3 {
		t.Fatalf("nova: %v", err)
	}
	sp := rt.gotBody["singleEmbeddingParams"].(map[string]any)
	if rt.gotBody["schemaVersion"] != "nova-multimodal-embed-v1" || rt.gotBody["taskType"] != "SINGLE_EMBEDDING" || sp["embeddingPurpose"] != "GENERIC_RETRIEVAL" || sp["text"].(map[string]any)["value"] != "hola" {
		t.Fatalf("nova request: %v", rt.gotBody)
	}
	if _, err = o.Embed(ctx, model("nova-embed"), []EmbedInput{{Image: []byte("PNGDATA"), ImageFormat: "png"}}, 256, ""); err != nil {
		t.Fatal(err)
	}
	img := rt.gotBody["singleEmbeddingParams"].(map[string]any)["image"].(map[string]any)
	if img["format"] != "png" || img["source"].(map[string]any)["bytes"] != base64.StdEncoding.EncodeToString([]byte("PNGDATA")) {
		t.Fatalf("nova image request: %v", img)
	}

	rt.reply = `{"embeddings":{"float":[[1,2],[3,4]]}}`
	if r, err = o.Embed(ctx, model("cohere-embed-v4"), []EmbedInput{{Text: "a"}, {Text: "b"}}, 0, ""); err != nil || len(r.Vectors) != 2 {
		t.Fatalf("cohere: %v", err)
	}
	if rt.gotBody["input_type"] != "search_document" || len(rt.gotBody["texts"].([]any)) != 2 || rt.gotBody["output_dimension"].(float64) != 1024 {
		t.Fatalf("cohere request: %v", rt.gotBody)
	}

	rt.reply = `{"data":[{"embedding":[0.1,0.2]}]}`
	if r, err = o.Embed(ctx, model("marengo-embed-3"), []EmbedInput{{Text: "hola"}}, 0, ""); err != nil || r.Dim != 2 {
		t.Fatalf("marengo: %v", err)
	}
	if rt.gotModel != "us.twelvelabs.marengo-embed-3-0-v1:0" || rt.gotBody["inputType"] != "text" || rt.gotBody["text"].(map[string]any)["inputText"] != "hola" {
		t.Fatalf("marengo request: %v %v", rt.gotModel, rt.gotBody)
	}
	if _, err = o.Embed(ctx, model("marengo-embed-3"), []EmbedInput{{Image: []byte("x"), ImageFormat: "png"}}, 0, ""); err != nil {
		t.Fatal(err)
	}
	if rt.gotBody["inputType"] != "image" || rt.gotBody["image"].(map[string]any)["mediaSource"].(map[string]any)["base64String"] == nil {
		t.Fatalf("marengo image request: %v", rt.gotBody)
	}

	rt.reply = `{"embedding":[1,2,3],"inputTextTokenCount":3}`
	if _, err = o.Embed(ctx, model("titan-embed-image"), []EmbedInput{{Text: "gato", Image: []byte("x")}}, 0, ""); err != nil {
		t.Fatal(err)
	}
	if rt.gotBody["inputText"] != "gato" || rt.gotBody["inputImage"] == nil || rt.gotBody["embeddingConfig"].(map[string]any)["outputEmbeddingLength"].(float64) != 384 {
		t.Fatalf("titan image request: %v", rt.gotBody)
	}
	if _, err = o.Embed(ctx, model("polly-neural"), []EmbedInput{{Text: "x"}}, 0, ""); !errors.Is(err, ErrUnsupported) {
		t.Errorf("a non embedding model: %v", err)
	}
	if _, err = o.Embed(ctx, model("titan-embed-v2"), nil, 0, ""); !errors.Is(err, ErrBadInput) {
		t.Errorf("empty input: %v", err)
	}
}

func TestRerankFormat(t *testing.T) {
	rt := &fakeRT{reply: `{"results":[{"index":2,"relevance_score":0.9},{"index":0,"relevance_score":0.1}]}`}
	hits, err := (&Ops{RT: rt}).Rerank(context.Background(), model("cohere-rerank-3-5"), "q", []string{"a", "b", "c"}, 2)
	if err != nil || len(hits) != 2 || hits[0].Index != 2 || hits[0].Score != 0.9 {
		t.Fatalf("%v %+v", err, hits)
	}
	if rt.gotBody["api_version"].(float64) != 2 || rt.gotBody["query"] != "q" || rt.gotBody["top_n"].(float64) != 2 || len(rt.gotBody["documents"].([]any)) != 3 {
		t.Fatalf("request: %v", rt.gotBody)
	}
	if _, err = (&Ops{RT: rt}).Rerank(context.Background(), model("cohere-rerank-3-5"), " ", []string{"a"}, 1); !errors.Is(err, ErrBadInput) {
		t.Errorf("empty query: %v", err)
	}
}

// ---- images ----

func TestImageFormats(t *testing.T) {
	ctx := context.Background()
	png := base64.StdEncoding.EncodeToString([]byte("IMG"))
	rt := &fakeRT{reply: `{"seeds":[42],"finish_reasons":[null],"images":["` + png + `"]}`}
	o := &Ops{RT: rt}

	// text to image: blank canvas as sketch, weak control
	out, err := o.ImageOp(ctx, model("stability-image-control-sketch"), ImageRequest{Prompt: "una manzana", Size: "128x128", Format: "jpeg"})
	if err != nil || len(out) != 1 || string(out[0].Data) != "IMG" || out[0].Seed != 42 || out[0].Format != "jpeg" {
		t.Fatalf("generate: %v %+v", err, out)
	}
	if rt.gotModel != "us.stability.stable-image-control-sketch-v1:0" || rt.gotBody["prompt"] != "una manzana" || rt.gotBody["output_format"] != "jpeg" || rt.gotBody["control_strength"].(float64) != 0.1 {
		t.Fatalf("generate request: %v %v", rt.gotModel, rt.gotBody)
	}
	blank, _ := base64.StdEncoding.DecodeString(rt.gotBody["image"].(string))
	if !bytes.HasPrefix(blank, []byte("\x89PNG")) {
		t.Fatal("the canvas must be a PNG")
	}

	// inpaint needs a mask and a prompt
	if _, err = o.ImageOp(ctx, model("stability-image-inpaint"), ImageRequest{Image: []byte("a"), Prompt: "x"}); !errors.Is(err, ErrBadInput) {
		t.Errorf("inpaint without mask: %v", err)
	}
	if _, err = o.ImageOp(ctx, model("stability-image-inpaint"), ImageRequest{Image: []byte("a"), Mask: []byte("m")}); !errors.Is(err, ErrBadInput) {
		t.Errorf("inpaint without prompt: %v", err)
	}
	if _, err = o.ImageOp(ctx, model("stability-image-inpaint"), ImageRequest{Image: []byte("a"), Mask: []byte("m"), Prompt: "círculo", N: 2}); err != nil || rt.calls < 3 {
		t.Fatalf("inpaint: %v", err)
	}
	if rt.gotBody["mask"] == nil || rt.gotBody["image"] == nil {
		t.Fatalf("inpaint request: %v", rt.gotBody)
	}
	// edits with other field names
	if _, err = o.ImageOp(ctx, model("stability-style-transfer"), ImageRequest{Image: []byte("a"), Extra: map[string]any{"style_image": "S"}}); err != nil || rt.gotBody["init_image"] == nil || rt.gotBody["style_image"] != "S" {
		t.Fatalf("style transfer: %v %v", err, rt.gotBody)
	}
	if _, err = o.ImageOp(ctx, model("stability-image-search-replace"), ImageRequest{Image: []byte("a"), Prompt: "gato"}); !errors.Is(err, ErrBadInput) {
		t.Errorf("search-replace needs search_prompt: %v", err)
	}
	if _, err = o.ImageOp(ctx, model("stability-image-remove-background"), ImageRequest{}); !errors.Is(err, ErrBadInput) {
		t.Errorf("edit without image: %v", err)
	}
	if _, err = o.ImageOp(ctx, model("stability-fast-upscale"), ImageRequest{Image: []byte("a"), N: 9}); !errors.Is(err, ErrBadInput) {
		t.Errorf("too many images: %v", err)
	}
	// the model refuses
	rt.reply = `{"seeds":[1],"finish_reasons":["CONTENT_FILTERED"],"images":["` + png + `"]}`
	if _, err = o.ImageOp(ctx, model("stability-fast-upscale"), ImageRequest{Image: []byte("a")}); !errors.Is(err, ErrBadInput) || !strings.Contains(err.Error(), "CONTENT_FILTERED") {
		t.Errorf("filtered: %v", err)
	}
	if _, err = BlankCanvas("9999x10"); !errors.Is(err, ErrBadInput) {
		t.Errorf("canvas bounds: %v", err)
	}
}

// ---- vision through Converse ----

func TestAnalyzeBuildsAttachments(t *testing.T) {
	rt := &fakeRT{}
	o := &Ops{RT: rt}
	res, err := o.Analyze(context.Background(), model("nova-2-lite"), "sé breve", "¿qué fruta es?", []Attachment{{Kind: "image", Format: "png", Data: []byte("IMG")}, {Kind: "video", Format: "mp4", Data: []byte("VID")}}, 50)
	if err != nil || res.Text != "una manzana" || res.InTokens != 300 || res.OutTokens != 4 {
		t.Fatalf("%v %+v", err, res)
	}
	if aws.ToString(rt.conv.ModelId) != "us.amazon.nova-2-lite-v1:0" || len(rt.conv.Messages[0].Content) != 3 || len(rt.conv.System) != 1 || aws.ToInt32(rt.conv.InferenceConfig.MaxTokens) != 50 {
		t.Fatalf("converse input: %+v", rt.conv)
	}
	if _, ok := rt.conv.Messages[0].Content[0].(*rttypes.ContentBlockMemberImage); !ok {
		t.Error("image block first")
	}
	if _, ok := rt.conv.Messages[0].Content[1].(*rttypes.ContentBlockMemberVideo); !ok {
		t.Error("video block second")
	}
	if _, err = o.Analyze(context.Background(), model("voxtral-mini"), "", "x", []Attachment{{Kind: "image", Format: "png", Data: []byte("a")}}, 10); !errors.Is(err, ErrUnsupported) {
		t.Errorf("a text-only model must refuse images: %v", err)
	}
	if _, err = o.Analyze(context.Background(), model("nova-2-lite"), "", "x", []Attachment{{Kind: "image", Format: "bmp", Data: []byte("a")}}, 10); !errors.Is(err, ErrBadInput) {
		t.Errorf("image format: %v", err)
	}
	rt.err = errors.New("ResourceNotFoundException: Model use case details have not been submitted for this account")
	if _, err = o.Analyze(context.Background(), model("nova-2-lite"), "", "x", nil, 10); !errors.Is(err, ErrNoAccess) {
		t.Errorf("missing access must be ErrNoAccess: %v", err)
	}
}

func TestClassifyAWS(t *testing.T) {
	for msg, want := range map[string]error{
		"AccessDeniedException: not authorized":                      ErrNoAccess,
		"ValidationException: Model does not support audio modality": ErrUnsupported,
		"ValidationException: bad field":                             ErrBadInput,
	} {
		if err := ClassifyAWS(errors.New(msg)); !errors.Is(err, want) {
			t.Errorf("%q -> %v, want %v", msg, err, want)
		}
	}
	if ClassifyAWS(nil) != nil {
		t.Error("nil")
	}
}

// ---- Polly ----

type fakePolly struct {
	in    []*polly.SynthesizeSpeechInput
	voice []pollytypes.Voice
}

func (f *fakePolly) SynthesizeSpeech(_ context.Context, in *polly.SynthesizeSpeechInput, _ ...func(*polly.Options)) (*polly.SynthesizeSpeechOutput, error) {
	f.in = append(f.in, in)
	return &polly.SynthesizeSpeechOutput{AudioStream: io.NopCloser(strings.NewReader("MP3")), RequestCharacters: int32(len([]rune(aws.ToString(in.Text))))}, nil
}
func (f *fakePolly) DescribeVoices(context.Context, *polly.DescribeVoicesInput, ...func(*polly.Options)) (*polly.DescribeVoicesOutput, error) {
	return &polly.DescribeVoicesOutput{Voices: f.voice}, nil
}

func TestSpeak(t *testing.T) {
	ctx := context.Background()
	p := &fakePolly{}
	sp, err := Speak(ctx, p, model("polly-neural"), SpeakRequest{Text: "Hola", Lang: "es-US"})
	if err != nil || string(sp.Audio) != "MP3" || sp.Voice != "Lupe" || sp.ContentType != "audio/mpeg" || sp.Chars != 4 {
		t.Fatalf("%v %+v", err, sp)
	}
	in := p.in[0]
	if in.Engine != pollytypes.EngineNeural || in.OutputFormat != pollytypes.OutputFormatMp3 || in.VoiceId != "Lupe" || in.LanguageCode != "es-US" || in.TextType != pollytypes.TextTypeText {
		t.Fatalf("request: %+v", in)
	}
	if _, err = Speak(ctx, p, model("polly-generative"), SpeakRequest{Text: "Hi", Lang: "en-US", Rate: "90%", Format: "ogg"}); err != nil {
		t.Fatal(err)
	}
	in = p.in[1]
	if in.Engine != pollytypes.EngineGenerative || in.TextType != pollytypes.TextTypeSsml || !strings.Contains(aws.ToString(in.Text), `<prosody rate="90%">`) || in.OutputFormat != pollytypes.OutputFormatOggVorbis {
		t.Fatalf("ssml request: %+v", in)
	}
	long := strings.Repeat("Una frase corta. ", 400) // 6800 chars -> several calls
	p.in = nil
	if sp, err = Speak(ctx, p, model("polly-neural"), SpeakRequest{Text: long}); err != nil || len(p.in) < 3 || sp.Chars < 6000 {
		t.Fatalf("chunking: %v calls=%d", err, len(p.in))
	}
	for _, c := range p.in {
		if len([]rune(aws.ToString(c.Text))) > 3000 {
			t.Fatal("a chunk exceeds Polly's limit")
		}
	}
	if _, err = Speak(ctx, p, model("polly-neural"), SpeakRequest{Text: strings.Repeat("a", MaxSpeechChars+1)}); !errors.Is(err, ErrBadInput) {
		t.Errorf("too long: %v", err)
	}
	if _, err = Speak(ctx, p, model("polly-neural"), SpeakRequest{Text: " "}); !errors.Is(err, ErrBadInput) {
		t.Errorf("empty: %v", err)
	}
	if _, err = Speak(ctx, p, model("polly-neural"), SpeakRequest{Text: "x", Format: "wav"}); !errors.Is(err, ErrBadInput) {
		t.Errorf("format: %v", err)
	}
	p.voice = []pollytypes.Voice{{Id: "Mia", Name: aws.String("Mia"), LanguageCode: "es-MX", Gender: "Female", SupportedEngines: []pollytypes.Engine{"neural"}}}
	vs, err := ListVoices(ctx, p, "es-MX")
	if err != nil || len(vs) != 1 || vs[0].ID != "Mia" || vs[0].Engines[0] != "neural" {
		t.Fatalf("voices: %v %+v", err, vs)
	}
}

// ---- Transcribe ----

type fakeTR struct {
	started *transcribe.StartTranscriptionJobInput
	status  trtypes.TranscriptionJobStatus
	uri     string
}

func (f *fakeTR) StartTranscriptionJob(_ context.Context, in *transcribe.StartTranscriptionJobInput, _ ...func(*transcribe.Options)) (*transcribe.StartTranscriptionJobOutput, error) {
	f.started = in
	return &transcribe.StartTranscriptionJobOutput{}, nil
}
func (f *fakeTR) GetTranscriptionJob(_ context.Context, in *transcribe.GetTranscriptionJobInput, _ ...func(*transcribe.Options)) (*transcribe.GetTranscriptionJobOutput, error) {
	return &transcribe.GetTranscriptionJobOutput{TranscriptionJob: &trtypes.TranscriptionJob{TranscriptionJobStatus: f.status, LanguageCode: "es-US", Transcript: &trtypes.Transcript{TranscriptFileUri: aws.String(f.uri)}}}, nil
}

type fakeStage struct{ puts, dels []string }

func (s *fakeStage) Put(_ context.Context, key string, _ []byte, _ string) (string, error) {
	s.puts = append(s.puts, key)
	return "s3://b/" + key, nil
}
func (s *fakeStage) Delete(_ context.Context, key string) error {
	s.dels = append(s.dels, key)
	return nil
}

const awsTranscript = `{"results":{"transcripts":[{"transcript":"Hola amigos. Buenas tardes a todos"}],"items":[
{"type":"pronunciation","start_time":"0.04","end_time":"0.4","speaker_label":"spk_0","alternatives":[{"content":"Hola"}]},
{"type":"pronunciation","start_time":"0.5","end_time":"1.1","speaker_label":"spk_0","alternatives":[{"content":"amigos"}]},
{"type":"punctuation","alternatives":[{"content":"."}]},
{"type":"pronunciation","start_time":"1.5","end_time":"2.0","speaker_label":"spk_1","alternatives":[{"content":"Buenas"}]},
{"type":"pronunciation","start_time":"2.1","end_time":"2.9","speaker_label":"spk_1","alternatives":[{"content":"tardes"}]}]}}`

func TestTranscribeJobLifecycle(t *testing.T) {
	ctx := context.Background()
	httpSrv := newTranscriptServer(awsTranscript)
	defer httpSrv.Close()
	api, stage := &fakeTR{status: trtypes.TranscriptionJobStatusInProgress, uri: httpSrv.URL}, &fakeStage{}
	tr := &Transcriber{API: api, Stage: stage, Jobs: NewMemKV(), HTTP: httpSrv.Client(), Now: func() time.Time { return time.Unix(0, 0) }}
	job, err := tr.Start(ctx, StartRequest{Data: bytes.Repeat([]byte("a"), 1000), Format: "mp3", Lang: "es-US", Diarize: true, MaxSpeakers: 2, ProjectID: "p1", EstMinutes: 2})
	if err != nil || job.Status != "queued" || job.CostUSD != 0.048 {
		t.Fatalf("start: %v %+v", err, job)
	}
	in := api.started
	if aws.ToString(in.TranscriptionJobName) != "capsule-"+job.ID || in.MediaFormat != trtypes.MediaFormatMp3 || in.LanguageCode != "es-US" ||
		!aws.ToBool(in.Settings.ShowSpeakerLabels) || aws.ToInt32(in.Settings.MaxSpeakerLabels) != 2 || !strings.HasPrefix(aws.ToString(in.Media.MediaFileUri), "s3://b/ai-stage/") {
		t.Fatalf("job input: %+v", in)
	}
	if len(stage.puts) != 1 {
		t.Fatal("the audio must be staged")
	}
	got, err := tr.Load(ctx, job.ID)
	if err != nil || got.ProjectID != "p1" {
		t.Fatalf("load: %v", err)
	}
	if got, err = tr.Poll(ctx, got); err != nil || got.Status != "running" || len(stage.dels) != 0 {
		t.Fatalf("running: %v %+v", err, got)
	}
	api.status = trtypes.TranscriptionJobStatusCompleted
	if got, err = tr.Poll(ctx, got); err != nil || got.Status != "completed" || got.Result == nil {
		t.Fatalf("completed: %v %+v", err, got)
	}
	if len(stage.dels) != 1 || got.StageKey != "" {
		t.Error("the staged audio must be removed on completion")
	}
	r := got.Result
	if len(r.Segments) != 2 || r.Speakers != 2 || r.Segments[0].Text != "Hola amigos." || r.Segments[1].Speaker != "spk_1" || r.Duration != 2.9 || r.Language != "es-US" {
		t.Fatalf("segments: %+v", r)
	}
	srt, _, _ := r.Render("srt")
	if !strings.Contains(string(srt), "1\n00:00:00,040 --> 00:00:01,100\nSpeaker 1: Hola amigos.") {
		t.Fatalf("srt:\n%s", srt)
	}
	vtt, _, _ := r.Render("vtt")
	if !strings.HasPrefix(string(vtt), "WEBVTT\n\n00:00:00.040 --> 00:00:01.100") {
		t.Fatalf("vtt:\n%s", vtt)
	}
	txt, _, _ := r.Render("txt")
	if string(txt) != "Speaker 1: Hola amigos.\nSpeaker 2: Buenas tardes\n" {
		t.Fatalf("txt: %q", txt)
	}
	js, _, _ := r.Render("json")
	var back Transcript
	if json.Unmarshal(js, &back) != nil || len(back.Segments) != 2 {
		t.Fatal("json")
	}
	if _, _, err = r.Render("docx"); !errors.Is(err, ErrBadInput) {
		t.Error("unknown format")
	}
	if _, err = tr.Load(ctx, "nope"); !errors.Is(err, ErrJobNotFound) {
		t.Error("unknown job")
	}
}

func TestTranscribeValidation(t *testing.T) {
	tr := &Transcriber{API: &fakeTR{}, Stage: &fakeStage{}, Jobs: NewMemKV()}
	ctx := context.Background()
	for name, req := range map[string]StartRequest{
		"empty":    {Format: "mp3"},
		"format":   {Data: []byte("a"), Format: "aiff"},
		"speakers": {Data: []byte("a"), Format: "mp3", Diarize: true, MaxSpeakers: 1},
		"size":     {Data: make([]byte, MaxAudioBytes+1), Format: "mp3"},
	} {
		if _, err := tr.Start(ctx, req); !errors.Is(err, ErrBadInput) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// no language: identify it
	api := &fakeTR{}
	tr.API = api
	if _, err := tr.Start(ctx, StartRequest{Data: []byte("a"), Format: "wav"}); err != nil || !aws.ToBool(api.started.IdentifyLanguage) || api.started.Settings != nil {
		t.Fatalf("identify language: %v %+v", err, api.started)
	}
	for in, want := range map[string]string{"clip.MP3": "mp3", "audio/mpeg": "mp3", "audio/x-wav": "wav", "voice.m4a": "m4a", "audio/webm;codecs=opus": "webm", "a.txt": ""} {
		if got := AudioFormat(in); got != want {
			t.Errorf("AudioFormat(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- Nova Sonic helpers ----

func TestWAVRoundTrip(t *testing.T) {
	pcm := make([]byte, 3200)
	for i := range pcm {
		pcm[i] = byte(i)
	}
	w := WAV(pcm, 24000)
	back, rate, err := PCMFromWAV(w)
	if err != nil || rate != 24000 || !bytes.Equal(back, pcm) {
		t.Fatalf("round trip: %v rate=%d", err, rate)
	}
	if _, _, err = PCMFromWAV([]byte("nope")); !errors.Is(err, ErrBadInput) {
		t.Error("not a wav")
	}
	stereo := WAV(pcm, 16000)
	stereo[22] = 2
	if _, _, err = PCMFromWAV(stereo); !errors.Is(err, ErrBadInput) {
		t.Error("stereo must be refused")
	}
	if got := Resample16(make([]byte, 48000*2), 48000); len(got) != 16000*2 {
		t.Errorf("resample length %d", len(got))
	}
	if got := Resample16(pcm, 16000); len(got) != len(pcm) {
		t.Error("16 kHz passes through")
	}
}

// ---- costs and quotas ----

func TestCostEstimates(t *testing.T) {
	if got := EstimateTokens(model("nova-2-lite"), 1000, 1000); got != 0.0028 {
		t.Errorf("tokens: %v", got)
	}
	if got := EstimateImages(model("stability-image-inpaint"), 3); got != 0.12 {
		t.Errorf("images: %v", got)
	}
	if got := EstimateSpeech(model("polly-neural"), 1000); got != 0.016 {
		t.Errorf("speech: %v", got)
	}
	if got := EstimateMinutes(model("transcribe"), 10); got != 0.24 {
		t.Errorf("minutes: %v", got)
	}
	if got := EstimateRerank(model("cohere-rerank-3-5"), 250); got != 0.006 {
		t.Errorf("rerank: %v", got)
	}
}

func TestQuota(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 5, 23, 0, 0, 0, time.UTC)
	q := &Quota{KV: NewMemKV(), DailyUSD: 1.00, Now: func() time.Time { return now }}
	if err := q.Check(ctx, "project:a", 0.9); err != nil {
		t.Fatal(err)
	}
	q.Add(ctx, "project:a", 0.9)
	err := q.Check(ctx, "project:a", 0.2)
	var qe *QuotaError
	if !errors.As(err, &qe) || !errors.Is(err, ErrQuota) || qe.UsedUSD != 0.9 || qe.LimitUSD != 1 {
		t.Fatalf("over the cap: %v", err)
	}
	if err := q.Check(ctx, "project:b", 0.9); err != nil {
		t.Error("another project has its own budget")
	}
	used, limit := q.Usage(ctx, "project:a")
	if used != 0.9 || limit != 1 {
		t.Errorf("usage %v/%v", used, limit)
	}
	now = now.Add(2 * time.Hour) // next UTC day
	if err := q.Check(ctx, "project:a", 0.9); err != nil {
		t.Error("the budget resets each UTC day")
	}
	if err := (&Quota{KV: NewMemKV()}).Check(ctx, "x", 1e9); err != nil {
		t.Error("0 means unlimited")
	}
}
