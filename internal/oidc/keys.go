package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/pkg/crypto"
)

const settingsKeyName = "oidc_signing_key"

// SigningKey is an RSA key with its stable key id.
type SigningKey struct {
	KID     string
	Private *rsa.PrivateKey
}

// KeySet holds the active signing key plus optional previous keys that are
// still published (and accepted for verification) during a rotation.
type KeySet struct {
	Active   *SigningKey
	Previous []*SigningKey
}

// NewKeySet builds a key set from parsed keys.
func NewKeySet(active *rsa.PrivateKey, previous ...*rsa.PrivateKey) *KeySet {
	ks := &KeySet{Active: &SigningKey{KID: KidFor(&active.PublicKey), Private: active}}
	for _, p := range previous {
		ks.Previous = append(ks.Previous, &SigningKey{KID: KidFor(&p.PublicKey), Private: p})
	}
	return ks
}

// Lookup returns the public key for kid.
func (k *KeySet) Lookup(kid string) *rsa.PublicKey {
	if k.Active != nil && k.Active.KID == kid {
		return &k.Active.Private.PublicKey
	}
	for _, p := range k.Previous {
		if p.KID == kid {
			return &p.Private.PublicKey
		}
	}
	return nil
}

// JWK is one entry of the JWKS document.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS returns the public key set document.
func (k *KeySet) JWKS() map[string]any {
	keys := []JWK{}
	all := append([]*SigningKey{k.Active}, k.Previous...)
	for _, sk := range all {
		if sk == nil {
			continue
		}
		pub := sk.Private.PublicKey
		keys = append(keys, JWK{
			Kty: "RSA", Use: "sig", Alg: "RS256", Kid: sk.KID,
			N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	return map[string]any{"keys": keys}
}

// KidFor derives a stable key id from the public key (SHA-256 of its DER form).
func KidFor(pub *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])[:16]
}

// ParsePEMKey parses a PKCS#1 or PKCS#8 RSA private key (>= 2048 bits).
// Literal "\n" sequences (common in env files) are accepted.
func ParsePEMKey(s string) (*rsa.PrivateKey, error) {
	s = strings.TrimSpace(strings.ReplaceAll(s, `\n`, "\n"))
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("signing key is not valid PEM")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else if k8, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k8.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("signing key must be RSA")
		}
		key = rk
	} else {
		return nil, errors.New("cannot parse signing key (expected PKCS#1 or PKCS#8 RSA)")
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("signing key must be at least 2048 bits")
	}
	return key, nil
}

func encodePEM(k *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

// LoadKeySet resolves the signing keys. Precedence:
//  1. envPEM (CAPSULE_OIDC_SIGNING_KEY) is the active key; prevPEM
//     (CAPSULE_OIDC_PREVIOUS_SIGNING_KEY) is an optional second key kept in
//     the JWKS so tokens signed before a rotation still verify.
//  2. Otherwise a key stored (AES-GCM encrypted with the platform secret) in
//     platform_settings; generated once if absent.
func LoadKeySet(ctx context.Context, settings domain.SettingsRepository, secretKey, envPEM, prevPEM string) (*KeySet, error) {
	if strings.TrimSpace(envPEM) != "" {
		active, err := ParsePEMKey(envPEM)
		if err != nil {
			return nil, fmt.Errorf("CAPSULE_OIDC_SIGNING_KEY: %w", err)
		}
		var prev []*rsa.PrivateKey
		if strings.TrimSpace(prevPEM) != "" {
			p, err := ParsePEMKey(prevPEM)
			if err != nil {
				return nil, fmt.Errorf("CAPSULE_OIDC_PREVIOUS_SIGNING_KEY: %w", err)
			}
			prev = append(prev, p)
		}
		return NewKeySet(active, prev...), nil
	}

	stored, err := settings.Get(ctx, settingsKeyName)
	if err != nil {
		return nil, fmt.Errorf("reading stored signing key: %w", err)
	}
	if stored != "" {
		raw, err := base64.StdEncoding.DecodeString(stored)
		if err != nil {
			return nil, fmt.Errorf("decoding stored signing key: %w", err)
		}
		plain, err := crypto.Decrypt(raw, secretKey)
		if err != nil {
			return nil, fmt.Errorf("decrypting stored signing key (CAPSULE_SECRET_KEY changed?): %w", err)
		}
		var doc struct {
			Active   string   `json:"active"`
			Previous []string `json:"previous"`
		}
		if err := json.Unmarshal(plain, &doc); err != nil {
			return nil, fmt.Errorf("parsing stored signing key: %w", err)
		}
		active, err := ParsePEMKey(doc.Active)
		if err != nil {
			return nil, err
		}
		var prev []*rsa.PrivateKey
		for _, p := range doc.Previous {
			pk, err := ParsePEMKey(p)
			if err != nil {
				return nil, err
			}
			prev = append(prev, pk)
		}
		return NewKeySet(active, prev...), nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating signing key: %w", err)
	}
	plain, _ := json.Marshal(map[string]any{"active": encodePEM(key), "previous": []string{}})
	enc, err := crypto.Encrypt(plain, secretKey)
	if err != nil {
		return nil, fmt.Errorf("encrypting signing key: %w", err)
	}
	if err := settings.Set(ctx, settingsKeyName, base64.StdEncoding.EncodeToString(enc)); err != nil {
		return nil, fmt.Errorf("storing signing key: %w", err)
	}
	return NewKeySet(key), nil
}
