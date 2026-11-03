package data

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

// CGC verification errors; they map to CAPR 0x0201, 0x0202 and 0x0203 (PROTOCOL.md 11.2).
var (
	ErrCGCInvalid = errors.New("cgc: invalid token")
	ErrCGCExpired = errors.New("cgc: expired or not yet valid")
	ErrCGCReplay  = errors.New("cgc: jti already used")
)

// CGCKey is a public key accepted to verify connection tokens (the current one and the previous one for rotation).
type CGCKey struct {
	KID string
	Pub ed25519.PublicKey
}

// CGCVerifier validates cgc_ connection tokens locally (Ed25519 compact JWT), without the control plane.
// Single use is enforced with an in-memory jti cache that lives until exp+skew.
type CGCVerifier struct {
	Keys []CGCKey
	Skew time.Duration // default 30 s

	mu   sync.Mutex
	seen map[string]time.Time
}

type cgcClaims struct {
	Sub   string `json:"sub"`
	Route string `json:"route"`
	Iat   int64  `json:"iat"`
	Nbf   int64  `json:"nbf"`
	Exp   int64  `json:"exp"`
	Jti   string `json:"jti"`
	Kid   string `json:"kid"`
}

// Verify checks token (with its cgc_ prefix) for the route "project/service". It returns subject and jti for audit.
func (v *CGCVerifier) Verify(token, route string, now time.Time) (sub, jti string, err error) {
	skew := v.Skew
	if skew <= 0 {
		skew = 30 * time.Second
	}
	body, ok := strings.CutPrefix(token, "cgc_")
	if !ok {
		return "", "", ErrCGCInvalid
	}
	parts := strings.Split(body, ".")
	if len(parts) != 3 {
		return "", "", ErrCGCInvalid
	}
	hb, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, e3 := base64.RawURLEncoding.DecodeString(parts[2])
	if e1 != nil || e2 != nil || e3 != nil || len(sig) != ed25519.SignatureSize {
		return "", "", ErrCGCInvalid
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "EdDSA" {
		return "", "", ErrCGCInvalid
	}
	var c cgcClaims
	if json.Unmarshal(pb, &c) != nil {
		return "", "", ErrCGCInvalid
	}
	signed := []byte(parts[0] + "." + parts[1])
	valid := false
	kid := hdr.Kid
	if kid == "" {
		kid = c.Kid
	}
	for _, k := range v.Keys {
		if kid != "" && k.KID != "" && k.KID != kid {
			continue
		}
		if len(k.Pub) == ed25519.PublicKeySize && ed25519.Verify(k.Pub, signed, sig) {
			valid = true
			break
		}
	}
	if !valid || c.Route != route || c.Exp == 0 || c.Iat == 0 || c.Exp-c.Iat > 300 || len(c.Jti) < 16 {
		return "", "", ErrCGCInvalid
	}
	// the signature is valid from here on: expiry may be reported distinctly (it reveals nothing about the project)
	exp := time.Unix(c.Exp, 0)
	if now.After(exp.Add(skew)) {
		return "", "", ErrCGCExpired
	}
	if c.Nbf != 0 && now.Add(skew).Before(time.Unix(c.Nbf, 0)) {
		return "", "", ErrCGCExpired
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = make(map[string]time.Time)
	}
	if until, dup := v.seen[c.Jti]; dup && now.Before(until) {
		return c.Sub, c.Jti, ErrCGCReplay
	}
	v.seen[c.Jti] = exp.Add(skew)
	return c.Sub, c.Jti, nil
}

// Sweep drops expired jti entries.
func (v *CGCVerifier) Sweep(now time.Time) {
	v.mu.Lock()
	for k, until := range v.seen {
		if now.After(until) {
			delete(v.seen, k)
		}
	}
	v.mu.Unlock()
}
