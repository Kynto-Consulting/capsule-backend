package objstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type memMeta struct {
	buckets map[string]*BucketInfo
	creds   map[string]*Credential
	limits  map[string]Limits
}

func (m *memMeta) Bucket(_ context.Context, n string) (*BucketInfo, error) {
	if b, ok := m.buckets[n]; ok {
		return b, nil
	}
	return nil, ErrNotFound
}
func (m *memMeta) Credential(_ context.Context, ak string) (*Credential, error) {
	if c, ok := m.creds[ak]; ok {
		return c, nil
	}
	return nil, ErrNotFound
}
func (m *memMeta) Limits(_ context.Context, b string) (Limits, error) { return m.limits[b], nil }

type rig struct {
	st   *Store
	meta *memMeta
	ts   *httptest.Server
	cli  *s3.Client
}

func newRig(t *testing.T, tlsOn bool) *rig {
	t.Helper()
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	meta := &memMeta{buckets: map[string]*BucketInfo{}, creds: map[string]*Credential{}, limits: map[string]Limits{}}
	for _, b := range []string{"alpha-files", "beta-files"} {
		if err := st.CreateBucket(b); err != nil {
			t.Fatal(err)
		}
		meta.buckets[b] = &BucketInfo{Name: b, OrgID: "o1", ProjectID: "p1"}
		meta.creds["AK"+b] = &Credential{AccessKey: "AK" + b, Secret: "secret-" + b, Bucket: b}
		meta.limits[b] = Limits{ProjectBuckets: []string{"alpha-files", "beta-files"}, OrgBuckets: []string{"alpha-files", "beta-files"}}
	}
	h := &Server{Store: st, Meta: meta}
	var ts *httptest.Server
	hc := http.DefaultClient
	if tlsOn {
		ts = httptest.NewTLSServer(h)
		hc = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	} else {
		ts = httptest.NewServer(h)
	}
	t.Cleanup(ts.Close)
	return &rig{st, meta, ts, client(ts.URL, hc, "alpha-files", "secret-alpha-files")}
}

func client(url string, hc *http.Client, bucket, secret string) *s3.Client {
	o := s3.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(url), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider("AK"+bucket, secret, ""),
	}
	if hc != nil {
		o.HTTPClient = hc
	}
	return s3.New(o)
}

func TestRoundTripPlainAndTLS(t *testing.T) {
	for _, tlsOn := range []bool{false, true} { // TLS makes the SDK use aws-chunked streaming + trailer checksums
		r := newRig(t, tlsOn)
		ctx := context.Background()
		body := bytes.Repeat([]byte("capsule"), 50000)
		_, err := r.cli.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("alpha-files"), Key: aws.String("dir/a b+c.txt"),
			Body: bytes.NewReader(body), ContentType: aws.String("text/plain")})
		if err != nil {
			t.Fatalf("tls=%v put: %v", tlsOn, err)
		}
		g, err := r.cli.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("alpha-files"), Key: aws.String("dir/a b+c.txt")})
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(g.Body)
		if !bytes.Equal(got, body) || aws.ToString(g.ContentType) != "text/plain" {
			t.Fatalf("tls=%v body mismatch (%d vs %d)", tlsOn, len(got), len(body))
		}
		rg, err := r.cli.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("alpha-files"), Key: aws.String("dir/a b+c.txt"), Range: aws.String("bytes=3-9")})
		if err != nil {
			t.Fatal(err)
		}
		part, _ := io.ReadAll(rg.Body)
		if string(part) != string(body[3:10]) {
			t.Fatalf("range: %q", part)
		}
		if _, err := r.cli.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("alpha-files"), Key: aws.String("top.txt"), Body: strings.NewReader("x")}); err != nil {
			t.Fatal(err)
		}
		ls, err := r.cli.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("alpha-files"), Delimiter: aws.String("/")})
		if err != nil || len(ls.Contents) != 1 || len(ls.CommonPrefixes) != 1 || aws.ToString(ls.CommonPrefixes[0].Prefix) != "dir/" {
			t.Fatalf("list: %v %+v", err, ls)
		}
		ls, _ = r.cli.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("alpha-files"), Prefix: aws.String("dir/")})
		if len(ls.Contents) != 1 || aws.ToString(ls.Contents[0].Key) != "dir/a b+c.txt" {
			t.Fatalf("list prefix: %+v", ls.Contents)
		}
		if _, err := r.cli.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String("alpha-files"), Key: aws.String("top.txt")}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.cli.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String("alpha-files"), Key: aws.String("top.txt")}); err == nil {
			t.Fatal("deleted object still there")
		}
		if r.st.Usage("alpha-files") != int64(len(body)) {
			t.Fatalf("usage %d", r.st.Usage("alpha-files"))
		}
	}
}

func TestPagination(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	for i := 0; i < 25; i++ {
		_, err := r.cli.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String("alpha-files"), Key: aws.String("k" + string(rune('a'+i))), Body: strings.NewReader("v")})
		if err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	p := s3.NewListObjectsV2Paginator(r.cli, &s3.ListObjectsV2Input{Bucket: aws.String("alpha-files"), MaxKeys: aws.Int32(10)})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			t.Fatal(err)
		}
		n += len(page.Contents)
	}
	if n != 25 {
		t.Fatalf("paginated %d", n)
	}
}

func TestMultipart(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	b, k := aws.String("alpha-files"), aws.String("big.bin")
	cm, err := r.cli.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: b, Key: k})
	if err != nil {
		t.Fatal(err)
	}
	var parts []s3types.CompletedPart
	var want []byte
	for i := 1; i <= 3; i++ {
		data := bytes.Repeat([]byte{byte('a' + i)}, 1<<20)
		want = append(want, data...)
		up, err := r.cli.UploadPart(ctx, &s3.UploadPartInput{Bucket: b, Key: k, UploadId: cm.UploadId, PartNumber: aws.Int32(int32(i)), Body: bytes.NewReader(data)})
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, s3types.CompletedPart{ETag: up.ETag, PartNumber: aws.Int32(int32(i))})
	}
	lp, err := r.cli.ListParts(ctx, &s3.ListPartsInput{Bucket: b, Key: k, UploadId: cm.UploadId})
	if err != nil || len(lp.Parts) != 3 {
		t.Fatalf("listparts %v %v", err, lp)
	}
	out, err := r.cli.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: b, Key: k, UploadId: cm.UploadId,
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: parts}})
	if err != nil || !strings.HasSuffix(strings.Trim(aws.ToString(out.ETag), `"`), "-3") {
		t.Fatalf("complete: %v %v", err, out)
	}
	g, _ := r.cli.GetObject(ctx, &s3.GetObjectInput{Bucket: b, Key: k})
	got, _ := io.ReadAll(g.Body)
	if !bytes.Equal(got, want) {
		t.Fatal("multipart content mismatch")
	}
	cm2, _ := r.cli.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: b, Key: aws.String("x")})
	if _, err := r.cli.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{Bucket: b, Key: aws.String("x"), UploadId: cm2.UploadId}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.cli.ListParts(ctx, &s3.ListPartsInput{Bucket: b, Key: aws.String("x"), UploadId: cm2.UploadId}); err == nil {
		t.Fatal("aborted upload still listed")
	}
}

func TestAuthRejections(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	bad := client(r.ts.URL, nil, "alpha-files", "nope")
	if _, err := bad.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("alpha-files")}); err == nil || !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Fatalf("wrong secret: %v", err)
	}
	unk := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(r.ts.URL), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider("AKnone", "x", "")})
	if _, err := unk.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("alpha-files")}); err == nil || !strings.Contains(err.Error(), "InvalidAccessKeyId") {
		t.Fatalf("unknown key: %v", err)
	}
	if _, err := r.cli.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("beta-files")}); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("cross bucket: %v", err)
	}
	resp, _ := http.Get(r.ts.URL + "/alpha-files/x")
	if resp.StatusCode != 403 {
		t.Fatalf("anonymous private: %d", resp.StatusCode)
	}
	if _, err := r.cli.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("alpha-files")}); err == nil {
		t.Fatal("CreateBucket must be refused")
	}
}

func TestPublicRead(t *testing.T) {
	r := newRig(t, false)
	if _, err := r.cli.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("alpha-files"), Key: aws.String("p.txt"), Body: strings.NewReader("hello")}); err != nil {
		t.Fatal(err)
	}
	if resp, _ := http.Get(r.ts.URL + "/alpha-files/p.txt"); resp.StatusCode != 403 {
		t.Fatalf("private before: %d", resp.StatusCode)
	}
	r.meta.buckets["alpha-files"].Public = true
	resp, _ := http.Get(r.ts.URL + "/alpha-files/p.txt")
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "hello" {
		t.Fatalf("public: %d %q", resp.StatusCode, b)
	}
	req, _ := http.NewRequest("PUT", r.ts.URL+"/alpha-files/p.txt", strings.NewReader("x"))
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 403 {
		t.Fatalf("anonymous put: %d", resp.StatusCode)
	}
	if resp, _ := http.Get(r.ts.URL + "/alpha-files?list-type=2"); resp.StatusCode != 403 {
		t.Fatalf("anonymous list: %d", resp.StatusCode)
	}
}

func TestPresign(t *testing.T) {
	r := newRig(t, false)
	now := time.Now()
	const ak, sk = "AKalpha-files", "secret-alpha-files"
	put, err := Presign("PUT", r.ts.URL, "us-east-1", "alpha-files", "up/file one.txt", ak, sk, time.Minute, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("PUT", put, strings.NewReader("via presigned put"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("presigned put: %v %v", err, resp)
	}
	get, _ := Presign("GET", r.ts.URL, "us-east-1", "alpha-files", "up/file one.txt", ak, sk, time.Minute, now, nil)
	resp, _ = http.Get(get)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "via presigned put" {
		t.Fatalf("presigned get: %d %q", resp.StatusCode, b)
	}
	req, _ = http.NewRequest("DELETE", get, nil)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 403 {
		t.Fatalf("method swap: %d", resp.StatusCode)
	}
	if resp, _ := http.Get(strings.Replace(get, "file%20one", "other", 1)); resp.StatusCode != 403 {
		t.Fatalf("tampered: %d", resp.StatusCode)
	}
	old, _ := Presign("GET", r.ts.URL, "us-east-1", "alpha-files", "up/file one.txt", ak, sk, time.Second, now.Add(-time.Hour), nil)
	if resp, _ := http.Get(old); resp.StatusCode != 403 {
		t.Fatalf("expired: %d", resp.StatusCode)
	}
	ps := s3.NewPresignClient(r.cli)
	pr, err := ps.PresignGetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String("alpha-files"), Key: aws.String("up/file one.txt")}, s3.WithPresignExpires(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if resp, _ := http.Get(pr.URL); resp.StatusCode != 200 {
		t.Fatalf("sdk presign: %d", resp.StatusCode)
	}
	id, _ := r.st.InitUpload("alpha-files", "mp", "")
	pu, _ := Presign("PUT", r.ts.URL, "us-east-1", "alpha-files", "mp", ak, sk, time.Minute, now, map[string][]string{"partNumber": {"1"}, "uploadId": {id}})
	req, _ = http.NewRequest("PUT", pu, strings.NewReader("partdata"))
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 200 {
		t.Fatalf("presigned part: %d", resp.StatusCode)
	}
}

func TestQuotas(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	put := func(bucket, key string, n int) error {
		c := client(r.ts.URL, nil, bucket, "secret-"+bucket)
		_, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(make([]byte, n))})
		return err
	}
	r.meta.buckets["alpha-files"].MaxBytes = 100
	if err := put("alpha-files", "a", 80); err != nil {
		t.Fatal(err)
	}
	if err := put("alpha-files", "b", 30); err == nil || !strings.Contains(err.Error(), "QuotaExceeded") {
		t.Fatalf("bucket quota: %v", err)
	}
	if err := put("alpha-files", "a", 100); err != nil {
		t.Fatalf("overwrite within quota: %v", err)
	}
	r.meta.buckets["alpha-files"].MaxBytes = 0
	l := r.meta.limits["beta-files"]
	l.ProjectMax = 150
	r.meta.limits["beta-files"] = l
	if err := put("beta-files", "c", 40); err != nil {
		t.Fatal(err)
	}
	if err := put("beta-files", "d", 20); err == nil {
		t.Fatal("project quota not enforced")
	}
	l.ProjectMax, l.OrgMax = 0, 145
	r.meta.limits["beta-files"] = l
	if err := put("beta-files", "d", 10); err == nil {
		t.Fatal("org quota not enforced")
	}
	l.OrgMax = 0
	r.meta.buckets["beta-files"].MaxBytes = 100
	r.meta.limits["beta-files"] = l
	c := client(r.ts.URL, nil, "beta-files", "secret-beta-files")
	cm, _ := c.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: aws.String("beta-files"), Key: aws.String("m")})
	if _, err := c.UploadPart(ctx, &s3.UploadPartInput{Bucket: aws.String("beta-files"), Key: aws.String("m"), UploadId: cm.UploadId, PartNumber: aws.Int32(1), Body: bytes.NewReader(make([]byte, 50))}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UploadPart(ctx, &s3.UploadPartInput{Bucket: aws.String("beta-files"), Key: aws.String("m"), UploadId: cm.UploadId, PartNumber: aws.Int32(2), Body: bytes.NewReader(make([]byte, 50))}); err == nil {
		t.Fatal("part past the cap accepted")
	}
}

func TestRestoreFromDisk(t *testing.T) {
	r := newRig(t, false)
	if _, err := r.cli.PutObject(context.Background(), &s3.PutObjectInput{Bucket: aws.String("alpha-files"), Key: aws.String("keep/me"), Body: strings.NewReader("persist")}); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(r.st.root)
	if err != nil {
		t.Fatal(err)
	}
	o, err := st2.Stat("alpha-files", "keep/me")
	if err != nil || o.Size != 7 || st2.Usage("alpha-files") != 7 {
		t.Fatalf("reload: %v %+v", err, o)
	}
}

func TestValidBucketName(t *testing.T) {
	for n, ok := range map[string]bool{"abc": true, "a-b.c": true, "ab": false, "-ab": false, "Abc": false, "a..b": false, "ab_c": false} {
		if ValidBucketName(n) != ok {
			t.Errorf("%q", n)
		}
	}
	if err := (&Store{}).CreateBucket("X"); err == nil {
		t.Error("invalid name accepted")
	}
}
