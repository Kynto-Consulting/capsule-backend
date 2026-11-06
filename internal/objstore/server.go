package objstore

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// BucketInfo is what the control plane knows about a bucket.
type BucketInfo struct {
	Name      string
	OrgID     string
	ProjectID string
	Public    bool  // anonymous GET/HEAD of objects
	MaxBytes  int64 // per-bucket cap, <=0 unlimited
}

// Credential is a per-bucket access key. Secret is the plaintext secret (needed to verify SigV4).
type Credential struct {
	AccessKey string
	Secret    string
	Bucket    string
}

// Limits are the quota caps that apply to a bucket plus the sibling buckets sharing them.
type Limits struct {
	ProjectMax     int64 // <=0 unlimited
	OrgMax         int64
	ProjectBuckets []string
	OrgBuckets     []string
}

// Meta is the control-plane view the S3 server consults on every request.
type Meta interface {
	Bucket(ctx context.Context, name string) (*BucketInfo, error)
	Credential(ctx context.Context, accessKey string) (*Credential, error)
	Limits(ctx context.Context, bucket string) (Limits, error)
}

// Server speaks the S3 REST API (path-style) over a Store.
type Server struct {
	Store  *Store
	Meta   Meta
	Region string
	// StripPath maps the request path to the path the client signed (a rewriting proxy prefixes it).
	StripPath func(r *http.Request) string
	Now       func() time.Time
	Log       *slog.Logger
}

type s3Err struct {
	status int
	code   string
	msg    string
}

var (
	eAccess    = s3Err{403, "AccessDenied", "Access Denied"}
	eSig       = s3Err{403, "SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided."}
	eKey       = s3Err{403, "InvalidAccessKeyId", "The access key ID you provided does not exist."}
	eExpired   = s3Err{403, "ExpiredToken", "The request has expired."}
	eNoBucket  = s3Err{404, "NoSuchBucket", "The specified bucket does not exist."}
	eNoKey     = s3Err{404, "NoSuchKey", "The specified key does not exist."}
	eNoUpload  = s3Err{404, "NoSuchUpload", "The specified multipart upload does not exist."}
	eQuota     = s3Err{403, "QuotaExceeded", "The storage quota of this bucket, project or organization is exhausted."}
	eBadDigest = s3Err{400, "BadDigest", "The content hash you specified did not match what we received."}
	eInvalid   = s3Err{400, "InvalidRequest", "Invalid request."}
	ePart      = s3Err{400, "InvalidPart", "One or more of the specified parts could not be found."}
	eNotImpl   = s3Err{501, "NotImplemented", "A header or parameter you provided implies functionality that is not implemented."}
	eMethod    = s3Err{405, "MethodNotAllowed", "The specified method is not allowed against this resource."}
	eInternal  = s3Err{500, "InternalError", "We encountered an internal error. Please try again."}
)

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func writeXML(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, xml.Header)
	_ = xml.NewEncoder(w).Encode(v)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, e s3Err) {
	if r.Method == http.MethodHead {
		w.WriteHeader(e.status)
		return
	}
	writeXML(w, e.status, struct {
		XMLName  xml.Name `xml:"Error"`
		Code     string
		Message  string
		Resource string
	}{Code: e.code, Message: e.msg, Resource: r.URL.Path})
}

func cors(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, HEAD")
	h.Set("Access-Control-Allow-Headers", "*")
	h.Set("Access-Control-Expose-Headers", "ETag, Content-Length, Content-Range")
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	path := r.URL.Path
	if s.StripPath != nil {
		path = s.StripPath(r)
	}
	path = strings.TrimPrefix(path, "/")
	bucket, key, _ := strings.Cut(path, "/")
	q := r.URL.Query()

	cred, secret, auth, e := s.authenticate(r, "/"+path, bucket)
	if e != nil {
		// public buckets allow anonymous reads of objects
		if e.code == eAccess.code && auth == nil && key != "" && (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
			q.Get("uploadId") == "" && s.isPublic(r.Context(), bucket) {
			cred = nil
		} else {
			s.fail(w, r, *e)
			return
		}
	}
	if bucket == "" {
		s.listBuckets(w, r, cred)
		return
	}
	if cred != nil && cred.Bucket != bucket {
		s.fail(w, r, eAccess)
		return
	}
	if !s.Store.HasBucket(bucket) {
		s.fail(w, r, eNoBucket)
		return
	}
	if key == "" {
		s.bucketOp(w, r, bucket)
		return
	}
	s.objectOp(w, r, bucket, key, auth, secret)
}

func (s *Server) isPublic(ctx context.Context, bucket string) bool {
	b, err := s.Meta.Bucket(ctx, bucket)
	return err == nil && b.Public
}

// authenticate verifies the request. On failure it returns the S3 error; auth is nil when the
// request carried no credentials at all.
func (s *Server) authenticate(r *http.Request, path, bucket string) (*Credential, string, *parsedAuth, *s3Err) {
	a, err := parseAuth(r)
	if err != nil {
		if errors.Is(err, errSigMissing) {
			return nil, "", nil, &eAccess
		}
		return nil, "", a, &eInvalid
	}
	cred, err := s.Meta.Credential(r.Context(), a.AccessKey)
	if err != nil || cred == nil {
		return nil, "", a, &eKey
	}
	var verr error
	for _, host := range hostsFor(r) {
		if verr = a.verify(r, path, host, cred.Secret, s.now()); verr == nil {
			break
		}
	}
	switch {
	case errors.Is(verr, errSigExpired):
		return nil, "", a, &eExpired
	case verr != nil:
		return nil, "", a, &eSig
	}
	return cred, cred.Secret, a, nil
}

func hostsFor(r *http.Request) []string {
	h := []string{r.Host}
	if f := r.Header.Get("X-Forwarded-Host"); f != "" {
		h = append(h, strings.TrimSpace(strings.Split(f, ",")[0]))
	}
	return h
}

func (s *Server) listBuckets(w http.ResponseWriter, r *http.Request, c *Credential) {
	if c == nil || r.Method != http.MethodGet {
		s.fail(w, r, eAccess)
		return
	}
	type bkt struct{ Name, CreationDate string }
	out := struct {
		XMLName xml.Name `xml:"ListAllMyBucketsResult"`
		Owner   struct{ ID string }
		Buckets struct{ Bucket []bkt }
	}{}
	out.Owner.ID = "capsule"
	if s.Store.HasBucket(c.Bucket) {
		out.Buckets.Bucket = []bkt{{c.Bucket, "2020-01-01T00:00:00.000Z"}}
	}
	writeXML(w, 200, out)
}

func (s *Server) bucketOp(w http.ResponseWriter, r *http.Request, bucket string) {
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodHead:
		w.Header().Set("x-amz-bucket-region", s.region())
		w.WriteHeader(200)
	case r.Method == http.MethodGet && q.Has("location"):
		writeXML(w, 200, struct {
			XMLName xml.Name `xml:"LocationConstraint"`
			V       string   `xml:",chardata"`
		}{V: s.region()})
	case r.Method == http.MethodGet:
		s.listObjects(w, r, bucket)
	case r.Method == http.MethodPost && q.Has("delete"):
		s.deleteObjects(w, r, bucket)
	case r.Method == http.MethodPut || r.Method == http.MethodDelete:
		// buckets are provisioned by the control plane (capsule storage create/delete)
		s.fail(w, r, eAccess)
	default:
		s.fail(w, r, eNotImpl)
	}
}

func (s *Server) region() string {
	if s.Region == "" {
		return "us-east-1"
	}
	return s.Region
}

type xObject struct {
	Key          string
	LastModified string
	ETag         string
	Size         int64
	StorageClass string
}

func isoTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func (s *Server) listObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	q := r.URL.Query()
	v2 := q.Get("list-type") == "2"
	max, _ := strconv.Atoi(q.Get("max-keys"))
	if max <= 0 || max > 1000 {
		max = 1000
	}
	prefix, delim := q.Get("prefix"), q.Get("delimiter")
	after := q.Get("marker")
	if v2 {
		after = q.Get("start-after")
		if t := q.Get("continuation-token"); t != "" {
			raw, err := base64.RawURLEncoding.DecodeString(t)
			if err != nil {
				s.fail(w, r, eInvalid)
				return
			}
			after = string(raw)
		}
	}
	res, err := s.Store.List(bucket, prefix, delim, after, max)
	if err != nil {
		s.fail(w, r, eNoBucket)
		return
	}
	enc := func(x string) string { return x }
	encType := q.Get("encoding-type")
	if encType == "url" {
		enc = func(x string) string { return awsEscape(x, true) }
	}
	type cp struct{ Prefix string }
	out := struct {
		XMLName               xml.Name `xml:"ListBucketResult"`
		Name                  string
		Prefix                string
		Delimiter             string `xml:",omitempty"`
		MaxKeys               int
		EncodingType          string `xml:",omitempty"`
		IsTruncated           bool
		KeyCount              int       `xml:",omitempty"`
		ContinuationToken     string    `xml:",omitempty"`
		NextContinuationToken string    `xml:",omitempty"`
		StartAfter            string    `xml:",omitempty"`
		Marker                string    `xml:",omitempty"`
		NextMarker            string    `xml:",omitempty"`
		Contents              []xObject `xml:",omitempty"`
		CommonPrefixes        []cp      `xml:",omitempty"`
	}{Name: bucket, Prefix: enc(prefix), Delimiter: delim, MaxKeys: max, EncodingType: encType, IsTruncated: res.Truncated}
	for _, o := range res.Objects {
		out.Contents = append(out.Contents, xObject{enc(o.Key), isoTime(o.Modified), `"` + o.ETag + `"`, o.Size, "STANDARD"})
	}
	for _, p := range res.CommonPrefixes {
		out.CommonPrefixes = append(out.CommonPrefixes, cp{enc(p)})
	}
	if v2 {
		out.KeyCount = len(res.Objects) + len(res.CommonPrefixes)
		out.ContinuationToken = q.Get("continuation-token")
		out.StartAfter = enc(q.Get("start-after"))
		if res.Truncated {
			out.NextContinuationToken = base64.RawURLEncoding.EncodeToString([]byte(res.Next))
		}
	} else {
		out.Marker = enc(q.Get("marker"))
		if res.Truncated && delim != "" {
			out.NextMarker = enc(res.Next)
		}
	}
	writeXML(w, 200, out)
}

func (s *Server) deleteObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	var in struct {
		Quiet  bool
		Object []struct{ Key string }
	}
	if err := xml.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&in); err != nil || len(in.Object) > 1000 {
		s.fail(w, r, eInvalid)
		return
	}
	type del struct{ Key string }
	out := struct {
		XMLName xml.Name `xml:"DeleteResult"`
		Deleted []del    `xml:",omitempty"`
	}{}
	for _, o := range in.Object {
		_ = s.Store.Delete(bucket, o.Key)
		if !in.Quiet {
			out.Deleted = append(out.Deleted, del{o.Key})
		}
	}
	writeXML(w, 200, out)
}

// room is how many more bytes can be added to bucket (<0: unlimited), counting parts in flight.
func (s *Server) room(ctx context.Context, bucket string) (int64, error) {
	b, err := s.Meta.Bucket(ctx, bucket)
	if err != nil {
		return 0, err
	}
	lim, err := s.Meta.Limits(ctx, bucket)
	if err != nil {
		return 0, err
	}
	used := func(names []string) int64 {
		var t int64
		for _, n := range names {
			t += s.Store.Usage(n) + s.Store.Pending(n)
		}
		return t
	}
	best := int64(-1)
	apply := func(max, used int64) {
		if max <= 0 {
			return
		}
		left := max - used
		if left < 0 {
			left = 0
		}
		if best < 0 || left < best {
			best = left
		}
	}
	apply(b.MaxBytes, s.Store.Usage(bucket)+s.Store.Pending(bucket))
	apply(lim.ProjectMax, used(lim.ProjectBuckets))
	apply(lim.OrgMax, used(lim.OrgBuckets))
	return best, nil
}

func (s *Server) body(r *http.Request, a *parsedAuth, secret string) (io.Reader, string, int64, *s3Err) {
	// returns reader, expected sha256 (hex) and the declared decoded length (-1 unknown)
	length := r.ContentLength
	if d := r.Header.Get("X-Amz-Decoded-Content-Length"); d != "" {
		n, err := strconv.ParseInt(d, 10, 64)
		if err != nil {
			return nil, "", 0, &eInvalid
		}
		length = n
	}
	var rd io.Reader = r.Body
	hash := ""
	if a != nil {
		switch {
		case strings.HasPrefix(a.PayloadHash, "STREAMING-"):
			rd = newChunkReader(r.Body, a, secret)
		case a.PayloadHash != unsignedBody && len(a.PayloadHash) == 64:
			hash = a.PayloadHash
		}
	}
	return rd, hash, length, nil
}

func (s *Server) quotaGuard(w http.ResponseWriter, r *http.Request, bucket string, length, replacing int64) (int64, bool) {
	room, err := s.room(r.Context(), bucket)
	if err != nil {
		s.fail(w, r, eInternal)
		return 0, false
	}
	if room >= 0 {
		room += replacing
		if length > room {
			s.fail(w, r, eQuota)
			return 0, false
		}
	}
	return room, true
}

func (s *Server) storeErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		s.fail(w, r, eNoKey)
	case errors.Is(err, ErrQuota):
		s.fail(w, r, eQuota)
	case errors.Is(err, ErrBadDigest):
		s.fail(w, r, eBadDigest)
	case errors.Is(err, ErrNoUpload):
		s.fail(w, r, eNoUpload)
	case errors.Is(err, ErrBadPart):
		s.fail(w, r, ePart)
	case errors.Is(err, errSigMismatch):
		s.fail(w, r, eSig)
	case errors.Is(err, ErrBadChunk), errors.Is(err, ErrBadKey):
		s.fail(w, r, eInvalid)
	default:
		if s.Log != nil {
			s.Log.Error("objstore", "error", err, "path", r.URL.Path)
		}
		s.fail(w, r, eInternal)
	}
}

func (s *Server) objectOp(w http.ResponseWriter, r *http.Request, bucket, key string, a *parsedAuth, secret string) {
	q := r.URL.Query()
	write := r.Method == http.MethodPut || r.Method == http.MethodPost || r.Method == http.MethodDelete
	if write && a == nil {
		s.fail(w, r, eAccess)
		return
	}
	uid := q.Get("uploadId")
	switch {
	case r.Method == http.MethodPost && q.Has("uploads"):
		id, err := s.Store.InitUpload(bucket, key, r.Header.Get("Content-Type"))
		if err != nil {
			s.storeErr(w, r, err)
			return
		}
		writeXML(w, 200, struct {
			XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
			Bucket   string
			Key      string
			UploadId string
		}{Bucket: bucket, Key: key, UploadId: id})
	case r.Method == http.MethodPut && uid != "":
		s.putPart(w, r, bucket, uid, a, secret)
	case r.Method == http.MethodPost && uid != "":
		s.completeUpload(w, r, bucket, key, uid)
	case r.Method == http.MethodDelete && uid != "":
		if err := s.Store.AbortUpload(bucket, uid); err != nil {
			s.storeErr(w, r, err)
			return
		}
		w.WriteHeader(204)
	case r.Method == http.MethodGet && uid != "":
		s.listParts(w, r, bucket, key, uid)
	case r.Method == http.MethodPut:
		if r.Header.Get("X-Amz-Copy-Source") != "" {
			s.fail(w, r, eNotImpl)
			return
		}
		s.putObject(w, r, bucket, key, a, secret)
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		f, o, err := s.Store.OpenObject(bucket, key)
		if err != nil {
			s.fail(w, r, eNoKey)
			return
		}
		defer f.Close()
		h := w.Header()
		h.Set("ETag", `"`+o.ETag+`"`)
		if o.ContentType != "" {
			h.Set("Content-Type", o.ContentType)
		} else {
			h.Set("Content-Type", "application/octet-stream")
		}
		h.Set("Accept-Ranges", "bytes")
		http.ServeContent(w, r, "", o.Modified, f)
	case r.Method == http.MethodDelete:
		if err := s.Store.Delete(bucket, key); err != nil {
			s.storeErr(w, r, err)
			return
		}
		w.WriteHeader(204)
	default:
		s.fail(w, r, eMethod)
	}
}

func (s *Server) putObject(w http.ResponseWriter, r *http.Request, bucket, key string, a *parsedAuth, secret string) {
	rd, sum, length, e := s.body(r, a, secret)
	if e != nil {
		s.fail(w, r, *e)
		return
	}
	var replacing int64
	if o, err := s.Store.Stat(bucket, key); err == nil {
		replacing = o.Size
	}
	room, ok := s.quotaGuard(w, r, bucket, length, replacing)
	if !ok {
		return
	}
	o, err := s.Store.Put(bucket, key, rd, writeOpts{ContentType: r.Header.Get("Content-Type"), MaxBytes: room, WantSHA256: sum})
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+o.ETag+`"`)
	w.WriteHeader(200)
}

func (s *Server) putPart(w http.ResponseWriter, r *http.Request, bucket, uid string, a *parsedAuth, secret string) {
	n, err := strconv.Atoi(r.URL.Query().Get("partNumber"))
	if err != nil {
		s.fail(w, r, eInvalid)
		return
	}
	rd, sum, length, e := s.body(r, a, secret)
	if e != nil {
		s.fail(w, r, *e)
		return
	}
	var replacing int64
	if ps, err := s.Store.Parts(bucket, uid); err == nil {
		for _, p := range ps {
			if p.Number == n {
				replacing = p.Size
			}
		}
	}
	room, ok := s.quotaGuard(w, r, bucket, length, replacing)
	if !ok {
		return
	}
	etag, _, err := s.Store.PutPart(bucket, uid, n, rd, room, sum)
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+etag+`"`)
	w.WriteHeader(200)
}

func (s *Server) completeUpload(w http.ResponseWriter, r *http.Request, bucket, key, uid string) {
	var in struct {
		Part []struct {
			PartNumber int
			ETag       string
		}
	}
	if err := xml.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&in); err != nil {
		s.fail(w, r, eInvalid)
		return
	}
	want := make([]Part, len(in.Part))
	for i, p := range in.Part {
		want[i] = Part{Number: p.PartNumber, ETag: p.ETag}
	}
	// parts already counted as pending: completing replaces them by the object, so room is the whole cap
	var replacing int64
	if o, err := s.Store.Stat(bucket, key); err == nil {
		replacing = o.Size
	}
	room, err := s.room(r.Context(), bucket)
	if err != nil {
		s.fail(w, r, eInternal)
		return
	}
	if room >= 0 {
		room += replacing + s.Store.UploadSize(bucket, uid)
	}
	o, err := s.Store.CompleteUpload(bucket, uid, want, room)
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	writeXML(w, 200, struct {
		XMLName xml.Name `xml:"CompleteMultipartUploadResult"`
		Bucket  string
		Key     string
		ETag    string
	}{Bucket: bucket, Key: key, ETag: `"` + o.ETag + `"`})
}

func (s *Server) listParts(w http.ResponseWriter, r *http.Request, bucket, key, uid string) {
	ps, err := s.Store.Parts(bucket, uid)
	if err != nil {
		s.storeErr(w, r, err)
		return
	}
	type xp struct {
		PartNumber int
		ETag       string
		Size       int64
	}
	out := struct {
		XMLName  xml.Name `xml:"ListPartsResult"`
		Bucket   string
		Key      string
		UploadId string
		Part     []xp `xml:",omitempty"`
	}{Bucket: bucket, Key: key, UploadId: uid}
	for _, p := range ps {
		out.Part = append(out.Part, xp{p.Number, `"` + p.ETag + `"`, p.Size})
	}
	writeXML(w, 200, out)
}

// Escape helper for callers building public object URLs.
func ObjectPath(bucket, key string) string { return "/" + bucket + "/" + awsEscape(key, true) }
