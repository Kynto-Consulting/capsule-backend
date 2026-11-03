package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// cgc_ connection tokens (PROTOCOL 11.2): "cgc_" + compact JWT, EdDSA (Ed25519), at most 300 s of life, one use.

const (
	// CGCPrefix is the connection-token prefix.
	CGCPrefix = "cgc_"
	// CGCMaxLife is the longest a cgc_ token may live (exp - iat).
	CGCMaxLife = 300 * time.Second
	cgcSkew    = 30 * time.Second
)

// Errors of Verify. The authorize endpoint maps all of them to the same "unauthorized" answer.
var (
	ErrCGCMalformed = errors.New("gateway: malformed connection token")
	ErrCGCSignature = errors.New("gateway: connection token signature")
	ErrCGCExpired   = errors.New("gateway: connection token expired")
	ErrCGCReplayed  = errors.New("gateway: connection token already used")
	ErrCGCRoute     = errors.New("gateway: connection token route mismatch")
)

// CGCClaims are the payload claims.
type CGCClaims struct {
	Sub   string `json:"sub"`           // principal (user id)
	Route string `json:"route"`         // "<project slug>/<service>"
	Iat   int64  `json:"iat"`           //
	Nbf   int64  `json:"nbf,omitempty"` //
	Exp   int64  `json:"exp"`           //
	Jti   string `json:"jti"`           // >= 96 bits
	Kid   string `json:"kid,omitempty"` //
}

type cgcHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// Signer signs cgc_ tokens and verifies them with the current and the previous public key.
type Signer struct {
	priv ed25519.PrivateKey
	keys []signingKey // current first
	mu   sync.Mutex
	seen map[string]time.Time // jti -> forget-after
}

type signingKey struct {
	kid string
	pub ed25519.PublicKey
}

// KeyInfo is the public description of a verification key (served to the data plane).
type KeyInfo struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	X   string `json:"x"` // base64url(no padding) of the 32-byte public key
}

func kidOf(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}

// NewSigner builds a Signer from a base64 32-byte Ed25519 seed and, optionally, the base64 public key of the
// previous signing key. An empty seed returns (nil, nil): connection tokens are then not available.
func NewSigner(seedB64, previousPubB64 string) (*Signer, error) {
	if strings.TrimSpace(seedB64) == "" {
		return nil, nil
	}
	seed, err := decodeB64(seedB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s must be the base64 of a %d-byte Ed25519 seed", EnvSigningKey, ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	s := &Signer{priv: priv, keys: []signingKey{{kid: kidOf(pub), pub: pub}}, seen: map[string]time.Time{}}
	if strings.TrimSpace(previousPubB64) != "" {
		pb, err := decodeB64(previousPubB64)
		if err != nil || len(pb) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s must be the base64 of a %d-byte Ed25519 public key", EnvSigningPrev, ed25519.PublicKeySize)
		}
		s.keys = append(s.keys, signingKey{kid: kidOf(pb), pub: ed25519.PublicKey(pb)})
	}
	return s, nil
}

// Keys lists the accepted verification keys, current first.
func (s *Signer) Keys() []KeyInfo {
	out := make([]KeyInfo, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, KeyInfo{Kid: k.kid, Alg: "EdDSA", X: base64.RawURLEncoding.EncodeToString(k.pub)})
	}
	return out
}

// Issue signs a token for sub on route ("<slug>/<service>") valid for ttl (<= CGCMaxLife). It returns the token and
// its jti (the only part that may be logged).
func (s *Signer) Issue(sub, route string, now time.Time, ttl time.Duration) (token, jti string, exp time.Time, err error) {
	if ttl <= 0 || ttl > CGCMaxLife {
		ttl = CGCMaxLife
	}
	raw := make([]byte, 16) // 128 bits
	if _, err = rand.Read(raw); err != nil {
		return "", "", time.Time{}, err
	}
	jti = base64.RawURLEncoding.EncodeToString(raw)
	exp = now.Add(ttl)
	kid := s.keys[0].kid
	hb, _ := json.Marshal(cgcHeader{Alg: "EdDSA", Typ: "cgc", Kid: kid})
	pb, _ := json.Marshal(CGCClaims{Sub: sub, Route: route, Iat: now.Unix(), Exp: exp.Unix(), Jti: jti, Kid: kid})
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sig := ed25519.Sign(s.priv, []byte(signing))
	return CGCPrefix + signing + "." + base64.RawURLEncoding.EncodeToString(sig), jti, exp, nil
}

// Verify checks format, algorithm, signature, time window and route, and consumes the jti (single use).
// wantRoute is "<slug>/<service>" of the route being connected to.
func (s *Signer) Verify(token, wantRoute string, now time.Time) (*CGCClaims, error) {
	if !strings.HasPrefix(token, CGCPrefix) {
		return nil, ErrCGCMalformed
	}
	parts := strings.Split(strings.TrimPrefix(token, CGCPrefix), ".")
	if len(parts) != 3 {
		return nil, ErrCGCMalformed
	}
	hb, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, e3 := base64.RawURLEncoding.DecodeString(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, ErrCGCMalformed
	}
	var h cgcHeader
	if json.Unmarshal(hb, &h) != nil || h.Alg != "EdDSA" || (h.Typ != "" && h.Typ != "cgc") {
		return nil, ErrCGCSignature
	}
	signing := []byte(parts[0] + "." + parts[1])
	ok := false
	for _, k := range s.keys { // try every key: same work whatever the kid says
		if h.Kid != "" && h.Kid != k.kid {
			continue
		}
		if len(sig) == ed25519.SignatureSize && ed25519.Verify(k.pub, signing, sig) {
			ok = true
		}
	}
	if !ok {
		return nil, ErrCGCSignature
	}
	var c CGCClaims
	if json.Unmarshal(pb, &c) != nil || c.Sub == "" || c.Jti == "" || c.Exp == 0 {
		return nil, ErrCGCMalformed
	}
	if c.Exp-c.Iat > int64(CGCMaxLife/time.Second) || c.Exp <= c.Iat {
		return nil, ErrCGCMalformed
	}
	exp := time.Unix(c.Exp, 0)
	if now.After(exp.Add(cgcSkew)) {
		return nil, ErrCGCExpired
	}
	if c.Nbf != 0 && now.Add(cgcSkew).Before(time.Unix(c.Nbf, 0)) {
		return nil, ErrCGCExpired
	}
	if c.Route != wantRoute {
		return nil, ErrCGCRoute
	}
	if !s.consume(c.Jti, exp.Add(cgcSkew), now) {
		return nil, ErrCGCReplayed
	}
	return &c, nil
}

// consume records the jti until forgetAfter and reports false when it was already used.
func (s *Signer) consume(jti string, forgetAfter, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.seen) > 4096 {
		for k, t := range s.seen {
			if now.After(t) {
				delete(s.seen, k)
			}
		}
	}
	if t, dup := s.seen[jti]; dup && now.Before(t) {
		return false
	}
	s.seen[jti] = forgetAfter
	return true
}
