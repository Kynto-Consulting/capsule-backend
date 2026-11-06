//go:build awsreal

// Real calls against Bedrock, Transcribe and Polly with small inputs (about 20 cents in total).
// Run:  AWS_PROFILE=tumi-admin AWS_REGION=us-east-1 go test -tags awsreal -run Real -v -timeout 10m ./internal/aimm
// CAPSULE_AI_STAGE_BUCKET names an S3 bucket for the Transcribe test (default capsule-artifacts-598806201852).
package aimm

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kynto/capsule/backend/pkg/awsclient"
)

type memKV struct {
	mu sync.Mutex
	m  map[string]string
}

func (k *memKV) Get(_ context.Context, key string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.m[key], nil
}
func (k *memKV) Set(_ context.Context, key, v string, _ int) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil {
		k.m = map[string]string{}
	}
	k.m[key] = v
	return nil
}

func realEnv(t *testing.T) (*awsclient.Clients, *Catalog, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)
	c, err := awsclient.New(ctx, "us-east-1", "", "", "")
	if err != nil {
		t.Skip("no AWS credentials:", err)
	}
	cat := NewCatalog(c.BedrockCtl, "us-east-1")
	return c, cat, ctx
}

func must(t *testing.T, cat *Catalog, ctx context.Context, id string) Model {
	t.Helper()
	m, ok := cat.Get(ctx, id)
	if !ok || !m.Available {
		t.Skipf("model %s not available: %+v", id, m.Reason)
	}
	return m
}

func TestRealCatalog(t *testing.T) {
	_, cat, ctx := realEnv(t)
	ms := cat.Models(ctx)
	if !cat.Live() {
		t.Fatal("catalog fell back to the fixed list: the Bedrock control plane did not answer")
	}
	byCap := map[Capability]int{}
	for _, m := range ms {
		if m.Available {
			for _, c := range m.Capabilities {
				byCap[c]++
			}
		}
	}
	t.Logf("%d models; available by capability: %v", len(ms), byCap)
	for _, ci := range cat.Capabilities(ctx) {
		t.Logf("capability %-16s available=%v models=%d %s", ci.ID, ci.Available, ci.Models, ci.Reason)
	}
	for _, id := range []string{"stability-image-control-sketch", "nova-2-lite"} {
		m, _ := cat.Get(ctx, id)
		t.Logf("%s -> invoke %s available=%v %s", id, m.InvokeID, m.Available, m.Reason)
	}
}

func TestRealEmbedRerank(t *testing.T) {
	c, cat, ctx := realEnv(t)
	ops := &Ops{RT: c.Bedrock}
	for _, id := range []string{"titan-embed-v2", "nova-embed", "cohere-embed-v4", "marengo-embed-3"} {
		m := must(t, cat, ctx, id)
		r, err := ops.Embed(ctx, m, []EmbedInput{{Text: "hola mundo"}, {Text: "hello world"}}, 256, "document")
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		t.Logf("%s: %d vectors dim %d tokens %d", id, len(r.Vectors), r.Dim, r.Tokens)
	}
	m := must(t, cat, ctx, "cohere-rerank-3-5")
	hits, err := ops.Rerank(ctx, m, "capital de Francia", []string{"Paris es la capital de Francia", "El gato duerme", "Madrid es de España"}, 2)
	if err != nil || len(hits) != 2 || hits[0].Index != 0 {
		t.Fatalf("rerank: %v %+v", err, hits)
	}
}

func TestRealImagesAndVision(t *testing.T) {
	c, cat, ctx := realEnv(t)
	ops := &Ops{RT: c.Bedrock}
	m := must(t, cat, ctx, "stability-image-control-sketch")
	imgs, err := ops.ImageOp(ctx, m, ImageRequest{Prompt: "a red apple on a wooden table, photo", Size: "512x512", Format: "jpeg"})
	if err != nil || len(imgs) != 1 || len(imgs[0].Data) < 10000 {
		t.Fatalf("text to image: %v", err)
	}
	t.Logf("generated %d bytes", len(imgs[0].Data))
	rm := must(t, cat, ctx, "stability-image-remove-background")
	out, err := ops.ImageOp(ctx, rm, ImageRequest{Image: imgs[0].Data, Format: "png"})
	if err != nil || len(out[0].Data) == 0 {
		t.Fatalf("remove background: %v", err)
	}
	vm := must(t, cat, ctx, "nova-2-lite")
	a, err := ops.Analyze(ctx, vm, "", "What fruit is in the picture? One word.", []Attachment{{Kind: "image", Format: "jpeg", Data: imgs[0].Data}}, 30)
	if err != nil || !strings.Contains(strings.ToLower(a.Text), "apple") {
		t.Fatalf("vision: %v %+v", err, a)
	}
	t.Logf("vision answer %q tokens %d/%d", a.Text, a.InTokens, a.OutTokens)
}

func TestRealSpeechAndTranscribe(t *testing.T) {
	c, cat, ctx := realEnv(t)
	pm := must(t, cat, ctx, "polly-neural")
	sp, err := Speak(ctx, c.Polly, pm, SpeakRequest{Text: "Hola, esta es una prueba corta de voz.", Lang: "es-US"})
	if err != nil || len(sp.Audio) < 1000 {
		t.Fatalf("speak: %v", err)
	}
	t.Logf("polly: %d bytes, %d chars", len(sp.Audio), sp.Chars)
	bucket := os.Getenv("CAPSULE_AI_STAGE_BUCKET")
	if bucket == "" {
		bucket = "capsule-artifacts-598806201852"
	}
	tr := &Transcriber{API: c.Transcribe, Stage: &S3Stage{API: c.S3, Bucket: bucket}, Jobs: &memKV{}}
	job, err := tr.Start(ctx, StartRequest{Data: sp.Audio, Format: "mp3", Lang: "es-US", Diarize: true, MaxSpeakers: 2, EstMinutes: 0.1})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	for i := 0; i < 60 && job.Status != "completed" && job.Status != "failed"; i++ {
		time.Sleep(3 * time.Second)
		if job, err = tr.Poll(ctx, job); err != nil {
			t.Fatalf("poll: %v", err)
		}
	}
	if job.Status != "completed" {
		t.Fatalf("job ended %s: %s", job.Status, job.Error)
	}
	t.Logf("transcript: %q segments=%d", job.Result.Text, len(job.Result.Segments))
	if !strings.Contains(strings.ToLower(job.Result.Text), "prueba") {
		t.Errorf("unexpected transcript %q", job.Result.Text)
	}
	srt, _, _ := job.Result.Render("srt")
	t.Logf("srt:\n%s", srt)
	if job.StageKey != "" {
		t.Error("staged audio was not removed")
	}
}

func TestRealSonic(t *testing.T) {
	c, cat, ctx := realEnv(t)
	for _, id := range []string{"nova-2-sonic", "nova-2-5-sonic"} {
		m := must(t, cat, ctx, id)
		pm := must(t, cat, ctx, "polly-neural")
		sp, err := Speak(ctx, c.Polly, pm, SpeakRequest{Text: "Hello, what is two plus two?", Lang: "en-US", Format: "pcm"})
		if err != nil {
			t.Fatal(err)
		}
		res, err := TalkFile(ctx, c.Bedrock, m, SonicConfig{}, sp.Audio, 80*time.Second)
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		t.Logf("%s heard=%q answer=%q audio=%d bytes tokens %d/%d", id, res.Heard, res.Answer, len(res.Audio), res.InTokens, res.OutTokens)
		if !bytes.Equal(res.Audio[:0], nil) || len(res.Audio) == 0 {
			t.Errorf("%s: no audio answer", id)
		}
	}
}
