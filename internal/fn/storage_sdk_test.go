package fn

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/objstore"
)

type objMeta struct{ bucket, ak, secret string }

func (m objMeta) Bucket(_ context.Context, n string) (*objstore.BucketInfo, error) {
	if n != m.bucket {
		return nil, objstore.ErrNotFound
	}
	return &objstore.BucketInfo{Name: n, OrgID: "o1", ProjectID: "p1"}, nil
}
func (m objMeta) Credential(_ context.Context, ak string) (*objstore.Credential, error) {
	if ak != m.ak {
		return nil, objstore.ErrNotFound
	}
	return &objstore.Credential{AccessKey: m.ak, Secret: m.secret, Bucket: m.bucket}, nil
}
func (m objMeta) Limits(context.Context, string) (objstore.Limits, error) {
	return objstore.Limits{ProjectBuckets: []string{m.bucket}, OrgBuckets: []string{m.bucket}}, nil
}

// ctx.storage of the SDK does a real signed PUT/GET/HEAD against Capsule's own object store, with the access that a
// `storage:<name>` scope resolves to through Service.Claim (the same path a run takes). Skipped without node or the SDK checkout.
func TestCtxStorageDoesRealPutsAgainstTheObjectStore(t *testing.T) {
	sdk, _ := filepath.Abs("../../../packages/capsule-fn")
	if _, err := os.Stat(filepath.Join(sdk, "node_modules", "tsx")); err != nil {
		t.Skip("packages/capsule-fn with its node_modules is not available here")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}

	st, err := objstore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateBucket("biblioteca"); err != nil {
		t.Fatal(err)
	}
	meta := objMeta{bucket: "biblioteca", ak: "AKbiblioteca", secret: "secret-biblioteca"}
	ts := httptest.NewServer(&objstore.Server{Store: st, Meta: meta})
	defer ts.Close()

	e := newEnv(t)
	e.svc.Storage = func(_ context.Context, _ uuid.UUID, name string) (map[string]string, error) {
		if name != "biblioteca" {
			return nil, ErrNotFound
		}
		return map[string]string{"endpoint": ts.URL, "bucket": "biblioteca", "access_key_id": meta.ak, "secret_access_key": meta.secret, "region": "us-east-1"}, nil
	}
	ctx := context.Background()
	f := e.deploy(t, Spec{Name: "migrar", Scopes: []string{"storage:biblioteca"}})
	e.svc.Enqueue(ctx, f, TriggerAPI, "user:ana", nil)
	a, err := e.svc.Claim(ctx, "nodo-1")
	if err != nil || a == nil {
		t.Fatalf("claim: %v", err)
	}

	cmd := exec.Command(node, "--import", "tsx", "test/storage-smoke.ts")
	cmd.Dir = sdk
	cmd.Env = append(os.Environ(), "SMOKE_BUCKET=biblioteca")
	for k, v := range a.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("node: %v\n%s", err, stderr.String())
		}
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("node did not finish")
	}
	var out struct {
		PutBytes          int               `json:"putBytes"`
		GetEqual          bool              `json:"getEqual"`
		GetText           string            `json:"getText"`
		HeadSize          int               `json:"headSize"`
		HeadMissing       interface{}       `json:"headMissing"`
		OtherScope        string            `json:"otherScope"`
		UploadSize        int               `json:"uploadSize"`
		UploadEtagParts   string            `json:"uploadEtagParts"`
		UploadHeadSize    int               `json:"uploadHeadSize"`
		UploadMeta        map[string]string `json:"uploadMeta"`
		UploadContentType string            `json:"uploadContentType"`
		SmallSize         int               `json:"smallSize"`
		SmallMeta         map[string]string `json:"smallMeta"`
		WrongSize         string            `json:"wrongSize"`
		WrongSizeStored   bool              `json:"wrongSizeStored"`
		ListKeys          []string          `json:"listKeys"`
		ListPages         int               `json:"listPages"`
	}
	line := strings.TrimSpace(stdout.String())
	if err := json.Unmarshal([]byte(line[strings.LastIndex(line, "\n")+1:]), &out); err != nil {
		t.Fatalf("output %q: %v", line, err)
	}
	if !out.GetEqual || out.HeadSize != out.PutBytes || out.GetText != "hola desde la función" || out.HeadMissing != nil {
		t.Fatalf("%+v", out)
	}
	if !strings.Contains(out.OtherScope, "no storage:otro scope") {
		t.Fatalf("a bucket outside the scopes must be refused by the SDK: %q", out.OtherScope)
	}

	// Bucket.upload: a streamed multipart upload (3 x 5 MiB + tail) with UTF-8 metadata; a single PUT for a small source;
	// a source of the wrong size is aborted and leaves nothing; list pages one key at a time.
	const total = 3*5<<20 + 1234
	if out.UploadSize != total || out.UploadHeadSize != total || out.UploadEtagParts != "4" || out.UploadContentType != "application/pdf" {
		t.Fatalf("multipart upload: %+v", out)
	}
	if out.UploadMeta["source-path"] != `\\srv\Expedientes\García\escrito final.pdf` || out.UploadMeta["mtime"] != "2024-03-01T10:00:00Z" {
		t.Fatalf("metadata: %q", out.UploadMeta)
	}
	if out.SmallSize != len("pequeño") || out.SmallMeta["origen"] != "smb" {
		t.Fatalf("small upload: %+v", out)
	}
	if !strings.Contains(out.WrongSize, "expected") || out.WrongSizeStored {
		t.Fatalf("a wrong size must fail and store nothing: %q stored=%v", out.WrongSize, out.WrongSizeStored)
	}
	if strings.Join(out.ListKeys, "|") != "migracion/García/escrito final.pdf|migracion/nota.txt" || out.ListPages != 2 {
		t.Fatalf("list: %v in %d pages", out.ListKeys, out.ListPages)
	}
	if n := st.Pending("biblioteca"); n != 0 {
		t.Fatalf("%d bytes of multipart parts left behind (the failed upload was not aborted)", n)
	}

	// and the bytes are really in the store: read them back with an independent client (the AWS SDK)
	cli := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(ts.URL), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(meta.ak, meta.secret, ""), HTTPClient: http.DefaultClient})
	got, err := cli.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("biblioteca"), Key: aws.String("expedientes/exp-001.pdf")})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	if got.ContentLength == nil || int(*got.ContentLength) != out.PutBytes {
		t.Fatalf("stored size %v, want %d", got.ContentLength, out.PutBytes)
	}
	// wrong credentials never write: the scope only works with the access it resolved to
	bad := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(ts.URL), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(meta.ak, "otra-clave", ""), HTTPClient: http.DefaultClient})
	if _, err := bad.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("biblioteca"), Key: aws.String("x"), Body: strings.NewReader("x")}); err == nil {
		t.Fatal("a PUT with another secret must be refused")
	}
}
