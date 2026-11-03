package data

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func mustKey(t testing.TB) (ed25519.PublicKey, ssh.Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub, s
}

func newEd(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// mintCGC builds a cgc_ token like the control plane does (PROTOCOL.md 11.2).
func mintCGC(t testing.TB, priv ed25519.PrivateKey, kid, route string, exp time.Time, jti string) string {
	t.Helper()
	b := func(v any) string {
		j, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(j)
	}
	iat := exp.Add(-2 * time.Minute)
	body := b(map[string]any{"alg": "EdDSA", "typ": "cgc", "kid": kid}) + "." +
		b(map[string]any{"sub": "user-1", "route": route, "iat": iat.Unix(), "exp": exp.Unix(), "jti": jti})
	sig := ed25519.Sign(priv, []byte(body))
	return "cgc_" + body + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func helloFor(name string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:        name,
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
		SupportedVersions: []uint16{tls.VersionTLS13},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
	}
}

func writePair(t testing.TB, dir, name string, cert tls.Certificate) (string, string) {
	t.Helper()
	c, k := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	writePairAt(t, c, k, cert)
	return c, k
}

func writePairAt(t testing.TB, certPath, keyPath string, cert tls.Certificate) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}
