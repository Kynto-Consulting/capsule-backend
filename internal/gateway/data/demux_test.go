package data

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"testing"
	"time"
)

func TestClassifyTable(t *testing.T) {
	sn := BuiltinSniffers()
	pg := func(code uint32) []byte {
		b := make([]byte, 8)
		binary.BigEndian.PutUint32(b, 8)
		binary.BigEndian.PutUint32(b[4:], code)
		return b
	}
	tests := []struct {
		name string
		in   []byte
		kind Kind
		need bool
	}{
		{"empty", nil, KindUnknown, true},
		{"tls record", []byte{0x16, 0x03, 0x01, 0x02, 0x00}, KindTLS, false},
		{"tls first byte only", []byte{0x16}, KindUnknown, true},
		{"tls bad version byte", []byte{0x16, 0x04}, KindUnknown, false},
		{"pg ssl request", pg(pgSSLRequest), KindPGSSL, false},
		{"pg gss request", pg(pgGSSRequest), KindPGSSL, false},
		{"pg cancel request not served", pg(pgCancelReq), KindUnknown, false},
		{"pg protocol 3.0 startup in clear", append([]byte{0, 0, 0, 0x2a, 0, 3, 0, 0}, 'u'), KindUnknown, false},
		{"pg prefix 4 bytes", []byte{0, 0, 0, 8}, KindUnknown, true},
		{"pg prefix 7 bytes", pg(pgSSLRequest)[:7], KindUnknown, true},
		{"http get", []byte("GET / HTTP/1.1\r\n"), KindHTTP, false},
		{"http post", []byte("POST /x"), KindHTTP, false},
		{"http partial", []byte("GE"), KindUnknown, true},
		{"http h2 preface", []byte("PRI * HTTP/2.0"), KindHTTP, false},
		{"ssh banner", []byte("SSH-2.0-OpenSSH_9.6"), KindSSH, false},
		{"ssh partial", []byte("SS"), KindUnknown, true},
		{"garbage", []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4}, KindUnknown, false},
		{"mysql-ish handshake byte", []byte{0x4a, 0, 0, 0, 0x0a}, KindUnknown, false},
	}
	for _, tc := range tests {
		k, need := Classify(sn, tc.in)
		if k != tc.kind || need != tc.need {
			t.Errorf("%s: got (%q,%v) want (%q,%v)", tc.name, k, need, tc.kind, tc.need)
		}
	}
}

// captureHello returns the exact bytes crypto/tls sends as a ClientHello.
func captureHello(t testing.TB, cfg *tls.Config) []byte {
	t.Helper()
	cl, sv := net.Pipe()
	go func() {
		tls.Client(cl, cfg).Handshake()
		cl.Close()
	}()
	sv.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8192)
	n, err := sv.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	sv.Close()
	return buf[:n]
}

func TestParseClientHelloRealHandshakes(t *testing.T) {
	cases := []struct {
		name string
		cfg  *tls.Config
		sni  string
		alpn []string
	}{
		{"sni only", &tls.Config{ServerName: "db.example.test", InsecureSkipVerify: true}, "db.example.test", nil},
		{"uppercase", &tls.Config{ServerName: "DB.Example.TEST", InsecureSkipVerify: true}, "db.example.test", nil},
		{"alpn capsule", &tls.Config{ServerName: "tcp.apps.test", InsecureSkipVerify: true, NextProtos: []string{"capsule/1"}}, "tcp.apps.test", []string{"capsule/1"}},
		{"alpn postgresql", &tls.Config{ServerName: "p.db.test", InsecureSkipVerify: true, NextProtos: []string{"postgresql"}}, "p.db.test", []string{"postgresql"}},
		{"several alpn", &tls.Config{ServerName: "x.test", InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1", "ssh"}}, "x.test", []string{"h2", "http/1.1", "ssh"}},
		{"no sni (ip literal)", &tls.Config{ServerName: "127.0.0.1", InsecureSkipVerify: true}, "", nil},
		{"tls12 only", &tls.Config{ServerName: "old.test", InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}, "old.test", nil},
	}
	for _, c := range cases {
		raw := captureHello(t, c.cfg)
		need, err := HelloLen(raw, 16384)
		if err != nil || need != len(raw) {
			t.Fatalf("%s: HelloLen=%d err=%v len=%d", c.name, need, err, len(raw))
		}
		h, err := ParseClientHello(raw)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if h.SNI != c.sni {
			t.Errorf("%s: SNI %q want %q", c.name, h.SNI, c.sni)
		}
		if !equalStr(h.ALPN, c.alpn) {
			t.Errorf("%s: ALPN %v want %v", c.name, h.ALPN, c.alpn)
		}
		// the demux must agree with crypto/tls on what it would see
		for i := 5; i < len(raw); i += 17 { // every strict prefix needs more bytes, never a verdict
			if n, err := HelloLen(raw[:i], 16384); err != nil || n <= i {
				t.Fatalf("%s: prefix %d: need=%d err=%v", c.name, i, n, err)
			}
		}
	}
}

func equalStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseClientHelloVersions(t *testing.T) {
	raw := captureHello(t, &tls.Config{ServerName: "v.test", InsecureSkipVerify: true})
	h, _ := ParseClientHello(raw)
	has13 := false
	for _, v := range h.Versions {
		if v == tls.VersionTLS13 {
			has13 = true
		}
	}
	if !has13 {
		t.Fatalf("supported_versions %v must list TLS 1.3", h.Versions)
	}
}

// A ClientHello written by hand, byte by byte, with SNI "a.test" and ALPN "capsule/1" (independent of crypto/tls).
func handHello(sni string, alpn string) []byte {
	var ext []byte
	if sni != "" {
		name := append([]byte{0}, 0, byte(len(sni)))
		name = append(name, sni...)
		list := append([]byte{0, byte(len(name))}, name...)
		ext = append(ext, 0, 0, 0, byte(len(list)))
		ext = append(ext, list...)
	}
	if alpn != "" {
		p := append([]byte{byte(len(alpn))}, alpn...)
		l := append([]byte{0, byte(len(p))}, p...)
		ext = append(ext, 0, 0x10, 0, byte(len(l)))
		ext = append(ext, l...)
	}
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session id
	body = append(body, 0, 2, 0x13, 0x01) // one cipher suite
	body = append(body, 1, 0)             // compression
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return rec
}

func TestParseClientHelloByHand(t *testing.T) {
	raw := handHello("a.test", "capsule/1")
	if _, err := hex.DecodeString(hex.EncodeToString(raw)); err != nil {
		t.Fatal(err)
	}
	h, err := ParseClientHello(raw)
	if err != nil || h.SNI != "a.test" || !h.Offers("capsule/1") {
		t.Fatalf("%+v %v", h, err)
	}
	h, err = ParseClientHello(handHello("", ""))
	if err != nil || h.SNI != "" || len(h.ALPN) != 0 {
		t.Fatalf("no extensions: %+v %v", h, err)
	}
}

func TestParseClientHelloRejects(t *testing.T) {
	good := handHello("a.test", "")
	bad := map[string][]byte{
		"not tls":            []byte("GET / HTTP/1.1\r\n\r\n"),
		"truncated body":     good[:len(good)-3],
		"not a ClientHello":  append([]byte{0x16, 3, 1, 0, 5}, 2, 0, 0, 1, 0), // ServerHello type
		"zero length record": {0x16, 3, 1, 0, 0},
	}
	for n, b := range bad {
		need, err := HelloLen(b, 16384)
		if err == nil && need <= len(b) {
			if _, err = ParseClientHello(b); err == nil {
				t.Errorf("%s: accepted", n)
			}
		}
	}
	// size limit: a record announcing more than max is refused before reading it
	big := []byte{0x16, 3, 1, 0x3f, 0xff}
	if _, err := HelloLen(big, 1024); !errors.Is(err, ErrHelloTooLarge) {
		t.Errorf("limit: %v", err)
	}
}

func TestSNINormalisation(t *testing.T) {
	cases := map[string]string{
		"A.B.test":         "a.b.test",
		"a.b.test.":        "a.b.test",
		"":                 "",
		".":                "",
		"bad name.test":    "",
		"bad\x00.test":     "",
		"ünï.test":         "",
		"under_score.test": "under_score.test",
	}
	for in, want := range cases {
		if got := normalizeSNI([]byte(in)); got != want {
			t.Errorf("%q -> %q want %q", in, got, want)
		}
	}
	long := bytes.Repeat([]byte("a"), 254)
	if normalizeSNI(long) != "" {
		t.Error("longer than 253 must be rejected")
	}
}

func TestHostFromHTTPHead(t *testing.T) {
	cases := []struct {
		in       string
		host     string
		complete bool
	}{
		{"GET / HTTP/1.1\r\nHost: Web.Apps.Test\r\n\r\n", "web.apps.test", true},
		{"GET / HTTP/1.1\r\nHost: web.apps.test:8080\r\n\r\n", "web.apps.test", true},
		{"GET / HTTP/1.1\r\nUser-Agent: x\r\nhost:  a.test \r\nAccept: */*\r\n\r\n", "a.test", true},
		{"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n", "", true}, // not a DNS name: no route
		{"GET / HTTP/1.1\r\nHost: part", "", false},            // line still arriving: never trust it
		{"GET / HTTP/1.1\r\nHost: full.test\r\nAcc", "full.test", false},
		{"GET / HTTP/1.1\r\n\r\n", "", true},
	}
	for _, c := range cases {
		h, comp := HostFromHTTPHead([]byte(c.in))
		if h != c.host || comp != c.complete {
			t.Errorf("%q -> (%q,%v) want (%q,%v)", c.in, h, comp, c.host, c.complete)
		}
	}
}

func FuzzParseClientHello(f *testing.F) {
	f.Add(handHello("a.test", "capsule/1"))
	f.Add(handHello("", ""))
	f.Add([]byte{0x16, 3, 1, 0, 4, 1, 0, 0, 0})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	cl, _ := net.Pipe()
	_ = cl
	f.Fuzz(func(t *testing.T, b []byte) {
		need, err := HelloLen(b, 4096)
		if err == nil && need > 4096+5 {
			t.Fatalf("asks for %d bytes beyond the limit", need)
		}
		if err == nil && need <= len(b) {
			h, perr := ParseClientHello(b[:need])
			if perr == nil && (len(h.SNI) > 253 || len(h.ALPN) > 32) {
				t.Fatal("unbounded output")
			}
		}
		// the parser must also be safe on arbitrary input fed directly
		ParseClientHello(b)
	})
}

func FuzzClassify(f *testing.F) {
	for _, s := range []string{"GET / ", "SSH-2.0", "\x16\x03\x01", "\x00\x00\x00\x08\x04\xd2\x16\x2f"} {
		f.Add([]byte(s))
	}
	sn := BuiltinSniffers()
	f.Fuzz(func(t *testing.T, b []byte) {
		k, need := Classify(sn, b)
		if k != KindUnknown && need {
			t.Fatal("matched and need more at once")
		}
		// determinism on prefixes: a verdict for a prefix must not change when more bytes arrive
		if k != KindUnknown {
			if k2, _ := Classify(sn, append(append([]byte(nil), b...), 'x', 'y', 'z')); k2 != k {
				t.Fatalf("verdict changed with more bytes: %q -> %q", k, k2)
			}
		}
	})
}

func FuzzHostFromHTTPHead(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, _ := HostFromHTTPHead(b)
		if len(h) > 253 {
			t.Fatal("host too long")
		}
	})
}
