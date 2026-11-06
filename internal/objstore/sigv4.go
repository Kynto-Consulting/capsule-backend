package objstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AWS Signature Version 4 for the S3 API: verification of header-signed and presigned requests
// (what the server needs) and presigning (what the backend hands to clients). Pure, no dependencies.

const (
	algo         = "AWS4-HMAC-SHA256"
	unsignedBody = "UNSIGNED-PAYLOAD"
	maxPresign   = 7 * 24 * time.Hour
	maxSkew      = 15 * time.Minute
)

var (
	errSigMissing  = errors.New("missing authentication")
	errSigMalform  = errors.New("malformed authorization")
	errSigMismatch = errors.New("signature does not match")
	errSigExpired  = errors.New("request expired")
)

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func hexSHA256(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func signingKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

// awsEscape percent-encodes everything but the RFC 3986 unreserved set (and '/' when keepSlash).
func awsEscape(s string, keepSlash bool) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' || (c == '/' && keepSlash) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hexd[c>>4])
			b.WriteByte(hexd[c&15])
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values, skip string) string {
	type kv struct{ k, v string }
	var all []kv
	for k, vs := range q {
		if k == skip {
			continue
		}
		for _, v := range vs {
			all = append(all, kv{awsEscape(k, false), awsEscape(v, false)})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].k != all[j].k {
			return all[i].k < all[j].k
		}
		return all[i].v < all[j].v
	})
	parts := make([]string, len(all))
	for i, e := range all {
		parts[i] = e.k + "=" + e.v
	}
	return strings.Join(parts, "&")
}

func canonicalHeaders(r *http.Request, host string, signed []string) string {
	var b strings.Builder
	for _, h := range signed {
		var v string
		if h == "host" {
			v = host
		} else {
			v = strings.Join(r.Header.Values(http.CanonicalHeaderKey(h)), ",")
		}
		v = strings.Join(strings.Fields(v), " ")
		b.WriteString(h + ":" + v + "\n")
	}
	return b.String()
}

// parsedAuth is the common shape of both signing styles.
type parsedAuth struct {
	AccessKey, Date, Region, Service string
	SignedHeaders                    []string
	Signature                        string
	Time                             time.Time
	Presigned                        bool
	Expires                          time.Duration
	PayloadHash                      string
}

func parseCredential(c string) (ak, date, region, service string, ok bool) {
	p := strings.Split(c, "/")
	if len(p) != 5 || p[4] != "aws4_request" {
		return
	}
	return p[0], p[1], p[2], p[3], true
}

func parseAuth(r *http.Request) (*parsedAuth, error) {
	q := r.URL.Query()
	if q.Get("X-Amz-Algorithm") != "" {
		if q.Get("X-Amz-Algorithm") != algo {
			return nil, errSigMalform
		}
		a := &parsedAuth{Presigned: true, Signature: q.Get("X-Amz-Signature"), PayloadHash: unsignedBody}
		var ok bool
		if a.AccessKey, a.Date, a.Region, a.Service, ok = parseCredential(q.Get("X-Amz-Credential")); !ok {
			return nil, errSigMalform
		}
		t, err := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
		if err != nil {
			return nil, errSigMalform
		}
		a.Time = t
		n, err := strconv.Atoi(q.Get("X-Amz-Expires"))
		if err != nil || n < 1 || time.Duration(n)*time.Second > maxPresign {
			return nil, errSigMalform
		}
		a.Expires = time.Duration(n) * time.Second
		a.SignedHeaders = strings.Split(q.Get("X-Amz-SignedHeaders"), ";")
		if h := q.Get("X-Amz-Content-Sha256"); h != "" {
			a.PayloadHash = h
		}
		return a, nil
	}
	h := r.Header.Get("Authorization")
	if h == "" {
		return nil, errSigMissing
	}
	if !strings.HasPrefix(h, algo+" ") {
		return nil, errSigMalform
	}
	a := &parsedAuth{PayloadHash: r.Header.Get("X-Amz-Content-Sha256")}
	for _, part := range strings.Split(h[len(algo)+1:], ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "Credential":
			var ok bool
			if a.AccessKey, a.Date, a.Region, a.Service, ok = parseCredential(v); !ok {
				return nil, errSigMalform
			}
		case "SignedHeaders":
			a.SignedHeaders = strings.Split(v, ";")
		case "Signature":
			a.Signature = v
		}
	}
	ds := r.Header.Get("X-Amz-Date")
	if ds == "" {
		ds = r.Header.Get("Date")
	}
	t, err := time.Parse("20060102T150405Z", ds)
	if err != nil {
		if t, err = http.ParseTime(ds); err != nil {
			return nil, errSigMalform
		}
	}
	a.Time = t.UTC()
	if a.AccessKey == "" || a.Signature == "" || len(a.SignedHeaders) == 0 || a.PayloadHash == "" {
		if a.PayloadHash == "" && a.AccessKey != "" {
			a.PayloadHash = unsignedBody
		} else {
			return nil, errSigMalform
		}
	}
	return a, nil
}

// seedSignature computes the expected signature of r for the given secret. path is the request path
// as the client signed it (decoded), which differs from r.URL.Path behind a rewriting proxy.
func (a *parsedAuth) expected(r *http.Request, path, host, secret string) string {
	cq := canonicalQuery(r.URL.Query(), "X-Amz-Signature")
	creq := strings.Join([]string{
		r.Method, awsEscape(path, true), cq,
		canonicalHeaders(r, host, a.SignedHeaders),
		strings.Join(a.SignedHeaders, ";"), a.PayloadHash,
	}, "\n")
	scope := a.Date + "/" + a.Region + "/" + a.Service + "/aws4_request"
	sts := algo + "\n" + a.Time.UTC().Format("20060102T150405Z") + "\n" + scope + "\n" + hexSHA256([]byte(creq))
	return hex.EncodeToString(hmacSHA256(signingKey(secret, a.Date, a.Region, a.Service), sts))
}

func (a *parsedAuth) verify(r *http.Request, path, host, secret string, now time.Time) error {
	if a.Presigned {
		if now.After(a.Time.Add(a.Expires)) {
			return errSigExpired
		}
		if a.Time.After(now.Add(maxSkew)) {
			return errSigMalform
		}
	} else if d := now.Sub(a.Time); d > maxSkew || d < -maxSkew {
		return errSigExpired
	}
	if subtle.ConstantTimeCompare([]byte(a.expected(r, path, host, secret)), []byte(a.Signature)) != 1 {
		return errSigMismatch
	}
	return nil
}

// Presign returns a presigned URL for method on endpoint (scheme://host[:port]/prefix) path-style:
// <endpoint>/<bucket>/<key>. extra query parameters (partNumber, uploadId...) are signed too.
func Presign(method, endpoint, region, bucket, key, accessKey, secret string, expires time.Duration, now time.Time, extra url.Values) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "", errors.New("invalid endpoint")
	}
	if expires <= 0 || expires > maxPresign {
		return "", errors.New("expiry must be between 1 second and 7 days")
	}
	now = now.UTC()
	date := now.Format("20060102")
	path := strings.TrimRight(u.Path, "/") + "/" + bucket
	if key != "" {
		path += "/" + key
	}
	q := url.Values{}
	for k, v := range extra {
		q[k] = v
	}
	q.Set("X-Amz-Algorithm", algo)
	q.Set("X-Amz-Credential", accessKey+"/"+date+"/"+region+"/s3/aws4_request")
	q.Set("X-Amz-Date", now.Format("20060102T150405Z"))
	q.Set("X-Amz-Expires", strconv.Itoa(int(expires/time.Second)))
	q.Set("X-Amz-SignedHeaders", "host")
	fake := &http.Request{Method: method, Header: http.Header{}, URL: &url.URL{Path: path, RawQuery: q.Encode()}}
	a := &parsedAuth{Date: date, Region: region, Service: "s3", SignedHeaders: []string{"host"}, Time: now, PayloadHash: unsignedBody}
	sig := a.expected(fake, path, u.Host, secret)
	return u.Scheme + "://" + u.Host + awsEscape(path, true) + "?" + canonicalQuery(q, "") + "&X-Amz-Signature=" + sig, nil
}
