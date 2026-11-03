package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3t "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// fakeS3 is an in-memory S3 recording the calls the store makes.
type fakeS3 struct {
	mu       sync.Mutex
	objects  map[string][]byte
	meta     map[string]map[string]string
	parts    map[string][][]byte
	puts     int
	aborts   int
	creates  int
	failPart int // fail UploadPart number N (0 = never)
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: map[string][]byte{}, meta: map[string]map[string]string{}, parts: map[string][][]byte{}}
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	b, _ := io.ReadAll(in.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts++
	f.objects[*in.Key], f.meta[*in.Key] = b, in.Metadata
	return &s3.PutObjectOutput{}, nil
}
func (f *fakeS3) CreateMultipartUpload(_ context.Context, in *s3.CreateMultipartUploadInput, _ ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	f.meta["mp:"+*in.Key] = in.Metadata
	return &s3.CreateMultipartUploadOutput{UploadId: aws.String("u1")}, nil
}
func (f *fakeS3) UploadPart(_ context.Context, in *s3.UploadPartInput, _ ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	b, _ := io.ReadAll(in.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failPart != 0 && int(*in.PartNumber) == f.failPart {
		return nil, errors.New("part failed")
	}
	f.parts[*in.Key] = append(f.parts[*in.Key], b)
	return &s3.UploadPartOutput{ETag: aws.String("e")}, nil
}
func (f *fakeS3) CompleteMultipartUpload(_ context.Context, in *s3.CompleteMultipartUploadInput, _ ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[*in.Key] = bytes.Join(f.parts[*in.Key], nil)
	f.meta[*in.Key] = f.meta["mp:"+*in.Key]
	return &s3.CompleteMultipartUploadOutput{}, nil
}
func (f *fakeS3) AbortMultipartUpload(_ context.Context, in *s3.AbortMultipartUploadInput, _ ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.aborts++
	delete(f.parts, *in.Key)
	return &s3.AbortMultipartUploadOutput{}, nil
}
func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[*in.Key]
	if !ok {
		return nil, errors.New("NoSuchKey")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(b)), Metadata: f.meta[*in.Key]}, nil
}
func (f *fakeS3) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, *in.Key)
	return &s3.DeleteObjectOutput{}, nil
}
func (f *fakeS3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &s3.ListObjectsV2Output{}
	for k, v := range f.objects {
		if len(k) >= len(*in.Prefix) && k[:len(*in.Prefix)] == *in.Prefix {
			out.Contents = append(out.Contents, fakeObj(k, int64(len(v))))
		}
	}
	return out, nil
}

func TestS3StoreStreamsMultipartAndSinglePut(t *testing.T) {
	api := newFakeS3()
	st := NewS3Store(api, "b")
	st.part = 1024
	ctx := context.Background()

	data := bytes.Repeat([]byte("x"), 2500)
	n, err := st.Upload(ctx, "k/multi", map[string]string{"m": "1"}, bytes.NewReader(data))
	if err != nil || n != 2500 {
		t.Fatalf("multipart upload: %d %v", n, err)
	}
	if api.creates != 1 || len(api.parts["k/multi"]) != 3 || !bytes.Equal(api.objects["k/multi"], data) {
		t.Fatalf("expected 3 parts reassembling to the data, got creates=%d parts=%d", api.creates, len(api.parts["k/multi"]))
	}
	if api.meta["k/multi"]["m"] != "1" {
		t.Fatal("metadata lost on multipart upload")
	}
	// exact multiple of the part size: no empty trailing part
	if _, err := st.Upload(ctx, "k/exact", nil, bytes.NewReader(bytes.Repeat([]byte("y"), 2048))); err != nil || len(api.parts["k/exact"]) != 2 {
		t.Fatalf("exact multiple: %v parts=%d", err, len(api.parts["k/exact"]))
	}
	if _, err := st.Upload(ctx, "k/small", nil, bytes.NewReader([]byte("tiny"))); err != nil || api.puts != 1 || string(api.objects["k/small"]) != "tiny" {
		t.Fatalf("small upload should be one PutObject: %v puts=%d", err, api.puts)
	}
	if _, err := st.Upload(ctx, "k/empty", nil, bytes.NewReader(nil)); err != nil {
		t.Fatalf("empty upload: %v", err)
	}
	body, _, err := st.Download(ctx, "k/small")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(body); string(b) != "tiny" {
		t.Fatal("download mismatch")
	}
	if l, _ := st.List(ctx, "k/"); len(l) != 4 {
		t.Fatalf("list: %d", len(l))
	}
}

type failingReader struct {
	n   int
	err error
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, f.err
	}
	k := min(len(p), f.n)
	f.n -= k
	return k, nil
}

func TestS3StoreAbortsWhenSourceFailsOrPartFails(t *testing.T) {
	api := newFakeS3()
	st := NewS3Store(api, "b")
	st.part = 1024
	boom := errors.New("dump process died")
	if _, err := st.Upload(context.Background(), "k/bad", nil, &failingReader{n: 3000, err: boom}); !errors.Is(err, boom) {
		t.Fatalf("want source error, got %v", err)
	}
	if api.aborts != 1 {
		t.Fatalf("multipart upload not aborted (aborts=%d)", api.aborts)
	}
	if _, ok := api.objects["k/bad"]; ok {
		t.Fatal("partial object was created")
	}
	api2 := newFakeS3()
	api2.failPart = 2
	st2 := NewS3Store(api2, "b")
	st2.part = 1024
	if _, err := st2.Upload(context.Background(), "k/p", nil, bytes.NewReader(make([]byte, 5000))); err == nil || api2.aborts != 1 {
		t.Fatalf("part failure must abort: err=%v aborts=%d", err, api2.aborts)
	}
}

func fakeObj(k string, n int64) s3t.Object { return s3t.Object{Key: aws.String(k), Size: aws.Int64(n)} }
