package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	rttypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/aws-sdk-go-v2/service/polly"
	"github.com/aws/aws-sdk-go-v2/service/transcribe"
	trtypes "github.com/aws/aws-sdk-go-v2/service/transcribe/types"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/aimm"
	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitaudit"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// ---- fakes of the AWS side ----

type aiRT struct {
	mu     sync.Mutex
	bodies []map[string]any
	models []string
	reply  func(model string) string
}

func (f *aiRT) InvokeModel(_ context.Context, in *bedrockruntime.InvokeModelInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := map[string]any{}
	_ = json.Unmarshal(in.Body, &m)
	f.bodies, f.models = append(f.bodies, m), append(f.models, aws.ToString(in.ModelId))
	return &bedrockruntime.InvokeModelOutput{Body: []byte(f.reply(aws.ToString(in.ModelId)))}, nil
}
func (f *aiRT) Converse(_ context.Context, in *bedrockruntime.ConverseInput, _ ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseOutput, error) {
	return &bedrockruntime.ConverseOutput{
		Output: &rttypes.ConverseOutputMemberMessage{Value: rttypes.Message{Role: rttypes.ConversationRoleAssistant, Content: []rttypes.ContentBlock{&rttypes.ContentBlockMemberText{Value: "es una manzana"}}}},
		Usage:  &rttypes.TokenUsage{InputTokens: aws.Int32(100), OutputTokens: aws.Int32(5)},
	}, nil
}
func (f *aiRT) ConverseStream(context.Context, *bedrockruntime.ConverseStreamInput, ...func(*bedrockruntime.Options)) (*bedrockruntime.ConverseStreamOutput, error) {
	return nil, fmt.Errorf("not used")
}

type aiPolly struct{}

func (aiPolly) SynthesizeSpeech(_ context.Context, in *polly.SynthesizeSpeechInput, _ ...func(*polly.Options)) (*polly.SynthesizeSpeechOutput, error) {
	return &polly.SynthesizeSpeechOutput{AudioStream: io.NopCloser(strings.NewReader("MP3DATA")), RequestCharacters: 20}, nil
}
func (aiPolly) DescribeVoices(context.Context, *polly.DescribeVoicesInput, ...func(*polly.Options)) (*polly.DescribeVoicesOutput, error) {
	return &polly.DescribeVoicesOutput{}, nil
}

type aiTR struct{}

func (aiTR) StartTranscriptionJob(context.Context, *transcribe.StartTranscriptionJobInput, ...func(*transcribe.Options)) (*transcribe.StartTranscriptionJobOutput, error) {
	return &transcribe.StartTranscriptionJobOutput{}, nil
}
func (aiTR) GetTranscriptionJob(context.Context, *transcribe.GetTranscriptionJobInput, ...func(*transcribe.Options)) (*transcribe.GetTranscriptionJobOutput, error) {
	return &transcribe.GetTranscriptionJobOutput{TranscriptionJob: &trtypes.TranscriptionJob{TranscriptionJobStatus: trtypes.TranscriptionJobStatusInProgress}}, nil
}

type aiStage struct{ keys []string }

func (s *aiStage) Put(_ context.Context, k string, _ []byte, _ string) (string, error) {
	s.keys = append(s.keys, k)
	return "s3://stage/" + k, nil
}
func (s *aiStage) Delete(context.Context, string) error { return nil }

type memBuckets struct {
	mu   sync.Mutex
	data map[string][]byte
}

func (m *memBuckets) Get(_ context.Context, _ uuid.UUID, b, k string, max int64) ([]byte, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.data[b+"/"+k]
	if !ok {
		return nil, "", ErrBucketNotFound
	}
	if int64(len(d)) > max {
		return nil, "", ErrObjectTooLarge
	}
	return d, "text/plain", nil
}
func (m *memBuckets) Put(_ context.Context, _ uuid.UUID, b, k string, d []byte, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[b+"/"+k] = d
	return nil
}
func (m *memBuckets) List(_ context.Context, _ uuid.UUID, b, prefix string, _ int) ([]BucketObject, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []BucketObject
	for k, d := range m.data {
		if strings.HasPrefix(k, b+"/"+prefix) {
			out = append(out, BucketObject{Key: strings.TrimPrefix(k, b+"/"), Size: int64(len(d))})
		}
	}
	return out, nil
}

type auditCap struct {
	mu sync.Mutex
	es []gitaudit.Entry
}

func (a *auditCap) Append(_ context.Context, e gitaudit.Entry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.es = append(a.es, e)
	return nil
}

type aiEnv struct {
	router  http.Handler
	org     uuid.UUID
	project uuid.UUID
	rt      *aiRT
	buckets *memBuckets
	audit   *auditCap
	stage   *aiStage
	h       *AIMMHandler
}

func newAIEnv(t *testing.T, role string, dailyUSD float64) *aiEnv {
	t.Helper()
	e := &aiEnv{org: uuid.New(), project: uuid.New(), buckets: &memBuckets{data: map[string][]byte{}}, audit: &auditCap{}, stage: &aiStage{}}
	png := base64.StdEncoding.EncodeToString([]byte("PNGBYTES"))
	e.rt = &aiRT{reply: func(model string) string {
		switch {
		case strings.Contains(model, "titan-embed"):
			return `{"embedding":[1,0,0],"inputTextTokenCount":5}`
		case strings.Contains(model, "rerank"):
			return `{"results":[{"index":1,"relevance_score":0.8},{"index":0,"relevance_score":0.2}]}`
		case strings.Contains(model, "stability"):
			return `{"seeds":[7],"finish_reasons":[null],"images":["` + png + `"]}`
		}
		return `{}`
	}}
	kv := aimm.NewMemKV()
	WireC2(nil, gitaudit.NewRecorder(e.audit), nil)
	t.Cleanup(func() { WireC2(nil, nil, nil) })
	e.h = NewAIMMHandler(AIMMDeps{
		Orgs: objOrgs{fakeOrgRepo{role: role}}, Catalog: aimm.NewCatalog(nil, "us-east-1"), Ops: &aimm.Ops{RT: e.rt}, Polly: aiPolly{},
		Trans: &aimm.Transcriber{API: aiTR{}, Stage: e.stage, Jobs: kv}, Quota: &aimm.Quota{KV: kv, DailyUSD: dailyUSD}, Buckets: e.buckets, Cache: nil,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			next.ServeHTTP(w, req.WithContext(middleware.WithUser(req.Context(), &domain.User{ID: uuid.New()})))
		})
	})
	b := "/orgs/{orgID}/projects/{projectID}/ai"
	r.Get("/ai/models", e.h.ModelsRoute)
	r.Post(b+"/chat", e.h.Chat)
	r.Post(b+"/embeddings", e.h.Embeddings)
	r.Post(b+"/embeddings/search", e.h.SearchEmbeddings)
	r.Post(b+"/rerank", e.h.Rerank)
	r.Post(b+"/transcribe", e.h.Transcribe)
	r.Get(b+"/jobs/{jobID}", e.h.Job)
	r.Post(b+"/speech", e.h.Speech)
	r.Post(b+"/images", e.h.Images)
	r.Get(b+"/usage", e.h.Usage)
	e.router = r
	return e
}

func (e *aiEnv) do(method, suffix string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, fmt.Sprintf("/orgs/%s/projects/%s/ai%s", e.org, e.project, suffix), &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func (e *aiEnv) multipart(suffix string, fields map[string]string, files map[string][]byte) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	for k, v := range files {
		fw, _ := mw.CreateFormFile(k, k+".bin")
		_, _ = fw.Write(v)
	}
	_ = mw.Close()
	req := httptest.NewRequest("POST", fmt.Sprintf("/orgs/%s/projects/%s/ai%s", e.org, e.project, suffix), &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func code(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var e struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	return e.Error.Code
}

// ---- tests ----

func TestAIMMPermissionsByCapability(t *testing.T) {
	// readonly reads (embeddings, rerank, chat) but cannot use what produces files (speech, images, transcription)
	ro := newAIEnv(t, "readonly", 0)
	if rec := ro.do("POST", "/embeddings", map[string]any{"input": "hola"}); rec.Code != 200 {
		t.Fatalf("readonly embeddings: %d %s", rec.Code, rec.Body)
	}
	for _, c := range []struct{ path string }{{"/speech"}, {"/images"}, {"/transcribe"}} {
		if rec := ro.do("POST", c.path, map[string]any{"text": "x", "prompt": "x"}); rec.Code != http.StatusForbidden {
			t.Errorf("readonly %s: %d, want 403", c.path, rec.Code)
		}
	}
	// a member does both
	mem := newAIEnv(t, "member", 0)
	if rec := mem.do("POST", "/speech", map[string]any{"text": "hola"}); rec.Code != 200 {
		t.Fatalf("member speech: %d %s", rec.Code, rec.Body)
	}
	// a stranger does nothing
	none := newAIEnv(t, "", 0)
	if rec := none.do("POST", "/embeddings", map[string]any{"input": "hola"}); rec.Code != http.StatusForbidden {
		t.Errorf("non member: %d", rec.Code)
	}
	for c, atom := range map[aimm.Capability]string{aimm.CapEmbed: "project:read", aimm.CapChat: "project:read", aimm.CapRerank: "project:read",
		aimm.CapTTS: "storage:presign", aimm.CapSTT: "storage:presign", aimm.CapImageGenerate: "storage:presign", aimm.CapImageEdit: "storage:presign", aimm.CapSpeechToSpeech: "storage:presign"} {
		if got := capabilityAtom(c); got != atom {
			t.Errorf("capabilityAtom(%s) = %s, want %s", c, got, atom)
		}
	}
}

func TestAIMMModelsCatalog(t *testing.T) {
	e := newAIEnv(t, "member", 0)
	req := httptest.NewRequest("GET", "/ai/models?capability=tts&available=true", nil)
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	var out struct {
		Data         []aimm.Model          `json:"data"`
		Capabilities []aimm.CapabilityInfo `json:"capabilities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Data) != 3 || len(out.Capabilities) != len(aimm.AllCapabilities) {
		t.Fatalf("catalog: %v %s", err, rec.Body)
	}
	rec = httptest.NewRecorder()
	e.router.ServeHTTP(rec, httptest.NewRequest("GET", "/ai/models?capability=teleport", nil))
	if rec.Code != 422 {
		t.Errorf("unknown capability: %d", rec.Code)
	}
}

func TestAIMMEmbeddingsRerankAndErrors(t *testing.T) {
	e := newAIEnv(t, "member", 0)
	rec := e.do("POST", "/embeddings", map[string]any{"input": []string{"a", "b"}, "model": "titan-embed-v2"})
	var emb struct {
		Dimensions int         `json:"dimensions"`
		Vectors    [][]float64 `json:"vectors"`
		Cost       float64     `json:"cost_estimate_usd"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &emb)
	if rec.Code != 200 || emb.Dimensions != 3 || len(emb.Vectors) != 2 || emb.Cost <= 0 {
		t.Fatalf("embeddings: %d %s", rec.Code, rec.Body)
	}
	rec = e.do("POST", "/rerank", map[string]any{"query": "q", "documents": []string{"uno", "dos"}})
	var rr struct {
		Results []struct {
			Index    int
			Document string
		}
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &rr)
	if rec.Code != 200 || len(rr.Results) != 2 || rr.Results[0].Index != 1 || rr.Results[0].Document != "dos" {
		t.Fatalf("rerank: %d %s", rec.Code, rec.Body)
	}
	if rec = e.do("POST", "/embeddings", map[string]any{"input": "x", "model": "no-such-model"}); rec.Code != 404 || code(t, rec) != "MODEL_NOT_FOUND" {
		t.Errorf("unknown model: %d %s", rec.Code, rec.Body)
	}
	if rec = e.do("POST", "/embeddings", map[string]any{"input": "x", "model": "polly-neural"}); rec.Code != 422 {
		t.Errorf("model of another capability: %d", rec.Code)
	}
	if rec = e.do("POST", "/embeddings", map[string]any{"input": "x", "dimensions": 7}); rec.Code != 422 || code(t, rec) != "VALIDATION_ERROR" {
		t.Errorf("bad dimensions: %d %s", rec.Code, rec.Body)
	}
	if rec = e.do("POST", "/embeddings", map[string]any{}); rec.Code != 422 {
		t.Errorf("empty input: %d", rec.Code)
	}
}

func TestAIMMImagesGenerateEditAndSave(t *testing.T) {
	e := newAIEnv(t, "member", 0)
	e.buckets.data["media/seed.txt"] = []byte("x")
	rec := e.do("POST", "/images", map[string]any{"prompt": "una manzana", "n": 2, "size": "256x256", "save_to": "media/out/"})
	var out struct {
		Model  string `json:"model"`
		Images []struct {
			B64   string `json:"b64"`
			Saved string `json:"saved_to"`
		} `json:"images"`
		Cost float64 `json:"cost_estimate_usd"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || out.Model != "stability-image-control-sketch" || len(out.Images) != 2 || out.Cost != 0.14 {
		t.Fatalf("generate: %d %s", rec.Code, rec.Body)
	}
	if !strings.HasPrefix(out.Images[0].Saved, "media/out/image-") || string(e.buckets.data[out.Images[0].Saved]) != "PNGBYTES" {
		t.Fatalf("result not saved in the bucket: %+v keys=%v", out.Images, keys(e.buckets.data))
	}
	if e.rt.models[0] != "us.stability.stable-image-control-sketch-v1:0" {
		t.Errorf("model called: %s", e.rt.models[0])
	}
	// edit: the image comes from the bucket, inpaint needs a mask
	e.buckets.data["media/in.png"] = []byte("SRC")
	e.buckets.data["media/mask.png"] = []byte("MASK")
	rec = e.do("POST", "/images", map[string]any{"prompt": "círculo verde", "image_source": "media/in.png", "mask_source": "media/mask.png", "inline": "false", "save_to": "media/edited.png"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"capability":"image-edit"`) || strings.Contains(rec.Body.String(), `"b64"`) || string(e.buckets.data["media/edited.png"]) != "PNGBYTES" {
		t.Fatalf("edit: %d %s", rec.Code, rec.Body)
	}
	last := e.rt.bodies[len(e.rt.bodies)-1]
	if last["image"] != base64.StdEncoding.EncodeToString([]byte("SRC")) || last["mask"] != base64.StdEncoding.EncodeToString([]byte("MASK")) {
		t.Fatalf("edit body: %v", last)
	}
	// operation= names the service by its short name
	rec = e.do("POST", "/images", map[string]any{"image_source": "media/in.png", "operation": "remove-background"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"model":"stability-image-remove-background"`) {
		t.Fatalf("operation: %d %s", rec.Code, rec.Body)
	}
	if rec = e.do("POST", "/images", map[string]any{"image_source": "media/in.png", "operation": "teleport"}); rec.Code != 422 || !strings.Contains(rec.Body.String(), "remove-background") {
		t.Errorf("unknown operation must list the valid ones: %d %s", rec.Code, rec.Body)
	}
	if rec = e.do("POST", "/images", map[string]any{"prompt": "x", "image_source": "media/missing.png"}); rec.Code != 404 {
		t.Errorf("missing source object: %d %s", rec.Code, rec.Body)
	}
	if rec = e.do("POST", "/images", map[string]any{"prompt": "x", "n": 9}); rec.Code != 422 {
		t.Errorf("too many images: %d", rec.Code)
	}
}

func keys(m map[string][]byte) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	return k
}

func TestAIMMQuotaBlocksAndUsageReports(t *testing.T) {
	e := newAIEnv(t, "member", 0.10) // 10 cents a day
	if rec := e.do("POST", "/images", map[string]any{"prompt": "uno", "n": 1}); rec.Code != 200 {
		t.Fatalf("first image: %d %s", rec.Code, rec.Body)
	}
	rec := e.do("POST", "/images", map[string]any{"prompt": "dos", "n": 2}) // 14 cents more: over the cap
	if rec.Code != http.StatusTooManyRequests || code(t, rec) != "QUOTA_EXCEEDED" {
		t.Fatalf("over budget: %d %s", rec.Code, rec.Body)
	}
	if len(e.rt.models) != 1 {
		t.Error("a call over budget must not reach the model")
	}
	rec = e.do("GET", "/usage", nil)
	var u struct {
		Used, Limit float64
	}
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	u.Used, u.Limit = raw["used_usd"].(float64), raw["limit_usd"].(float64)
	if u.Used != 0.07 || u.Limit != 0.10 {
		t.Fatalf("usage: %s", rec.Body)
	}
}

func TestAIMMAuditHasNoContent(t *testing.T) {
	e := newAIEnv(t, "member", 0)
	secretPrompt := "mi prompt privado sobre la fusión de SuperCorp"
	if rec := e.do("POST", "/images", map[string]any{"prompt": secretPrompt}); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/embeddings", map[string]any{"input": secretPrompt}); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(e.audit.es) != 2 {
		t.Fatalf("audit entries: %d (the recorder may have rejected the metadata)", len(e.audit.es))
	}
	for _, en := range e.audit.es {
		b, _ := json.Marshal(en)
		if strings.Contains(string(b), "SuperCorp") || strings.Contains(string(b), "privado") {
			t.Fatalf("audit entry carries the prompt: %s", b)
		}
		if en.ResourceType != "ai_call" || !strings.HasPrefix(en.Action, "ai.") || en.Metadata["model"] == nil || en.Metadata["cost_estimate_usd"] == nil || en.Metadata["bytes_in"] == nil || en.ProjectID == nil {
			t.Errorf("audit entry incomplete: %+v", en)
		}
	}
	if e.audit.es[0].Action != "ai.image_generate" || e.audit.es[1].Action != "ai.embed" {
		t.Errorf("actions: %s, %s", e.audit.es[0].Action, e.audit.es[1].Action)
	}
}

func TestAIMMSpeechAndTranscribe(t *testing.T) {
	e := newAIEnv(t, "member", 0)
	rec := e.do("POST", "/speech", map[string]any{"text": "Hola mundo", "voice": "Lupe"})
	if rec.Code != 200 || rec.Body.String() != "MP3DATA" || rec.Header().Get("Content-Type") != "audio/mpeg" || rec.Header().Get("X-Capsule-Chars") != "20" || rec.Header().Get("X-Capsule-Cost-USD") == "" {
		t.Fatalf("speech: %d %q %v", rec.Code, rec.Body, rec.Header())
	}
	rec = e.do("POST", "/speech", map[string]any{"text": "Hola", "save_to": "media/audio/"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"saved_to":"media/audio/speech-`) {
		t.Fatalf("speech saved: %d %s", rec.Code, rec.Body)
	}
	if rec = e.do("POST", "/speech", map[string]any{"text": ""}); rec.Code != 422 {
		t.Errorf("empty text: %d", rec.Code)
	}

	rec = e.multipart("/transcribe", map[string]string{"lang": "es-US", "diarize": "true"}, map[string][]byte{"file": bytes.Repeat([]byte("a"), 2000)})
	if rec.Code != http.StatusBadRequest && rec.Code != 422 {
		// the multipart file name has no audio extension and the part no audio type
		t.Fatalf("an unknown audio format must be refused: %d %s", rec.Code, rec.Body)
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("lang", "es-US")
	_ = mw.WriteField("diarize", "true")
	fw, _ := mw.CreateFormFile("file", "reunion.mp3")
	_, _ = fw.Write(bytes.Repeat([]byte("a"), 2000))
	_ = mw.Close()
	req := httptest.NewRequest("POST", fmt.Sprintf("/orgs/%s/projects/%s/ai/transcribe", e.org, e.project), &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec = httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	var started struct {
		Job struct {
			ID, Status string
			Diarize    bool
		}
		Poll string
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &started)
	if rec.Code != http.StatusAccepted || started.Job.Status != "queued" || !started.Job.Diarize || len(e.stage.keys) != 1 {
		t.Fatalf("transcribe: %d %s", rec.Code, rec.Body)
	}
	rec = e.do("GET", "/jobs/"+started.Job.ID, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"running"`) {
		t.Fatalf("job state: %d %s", rec.Code, rec.Body)
	}
	if rec = e.do("GET", "/jobs/"+uuid.NewString(), nil); rec.Code != 404 {
		t.Errorf("unknown job: %d", rec.Code)
	}
	// a job of another project is not visible
	other := *e
	other.project = uuid.New()
	rec = other.do("GET", "/jobs/"+started.Job.ID, nil)
	if rec.Code != 404 {
		t.Errorf("job of another project: %d", rec.Code)
	}
}

func TestAIMMChatWithImageAndSearch(t *testing.T) {
	e := newAIEnv(t, "member", 0)
	rec := e.multipart("/chat", map[string]string{"prompt": "¿qué fruta es?"}, map[string][]byte{"image": []byte("PNG")})
	if rec.Code != 422 && rec.Code != 200 {
		t.Fatalf("chat: %d %s", rec.Code, rec.Body)
	}
	// the multipart part has no extension: the format is unknown, so it is refused clearly
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "image format") {
		t.Fatalf("unknown image format must be refused: %d %s", rec.Code, rec.Body)
	}
	rec = e.do("POST", "/chat", map[string]any{"prompt": "¿qué fruta es?", "image_base64": base64.StdEncoding.EncodeToString([]byte("PNG"))})
	if rec.Code != 422 { // base64 files have no name either
		t.Logf("json image without format: %d", rec.Code)
	}
	rec = e.do("POST", "/chat", map[string]any{"prompt": "hola"})
	var chat struct {
		Text  string  `json:"text"`
		Model string  `json:"model"`
		Cost  float64 `json:"cost_estimate_usd"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &chat)
	if rec.Code != 200 || chat.Text != "es una manzana" || chat.Model != "nova-2-lite" || chat.Cost <= 0 {
		t.Fatalf("chat: %d %s", rec.Code, rec.Body)
	}

	// similarity search over a bucket
	e.buckets.data["docs/a.txt"] = []byte("factura de luz")
	e.buckets.data["docs/b.md"] = []byte("receta de cocina")
	e.buckets.data["docs/pic.png"] = []byte("not text")
	rec = e.do("POST", "/embeddings/search", map[string]any{"query": "recibo", "bucket": "docs", "top_k": 1})
	var s struct {
		Documents, Skipped int
		Hits               []struct{ Key string }
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	if rec.Code != 200 || s.Documents != 2 || s.Skipped != 1 || len(s.Hits) != 1 {
		t.Fatalf("search: %d %s", rec.Code, rec.Body)
	}
	if rec = e.do("POST", "/embeddings/search", map[string]any{"query": "x", "bucket": "nope"}); rec.Code != 422 && rec.Code != 404 {
		t.Errorf("empty bucket: %d", rec.Code)
	}
}
