package data

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func FuzzParseMySQLSSLRequest(f *testing.F) {
	f.Add(sslRequestPacket())
	f.Add([]byte{})
	f.Add(make([]byte, mysqlSSLReqTotal))
	f.Fuzz(func(t *testing.T, b []byte) {
		caps, err := parseMySQLSSLRequest(b)
		if err == nil && (len(b) != mysqlSSLReqTotal || caps&capSSL == 0) {
			t.Fatalf("accepted %x", b)
		}
	})
}

func FuzzParseMySQLGreeting(f *testing.F) {
	g := buildMySQLGreeting(1, mysqlSalt(20))
	f.Add(g[4:])
	f.Add([]byte{10})
	f.Add([]byte{10, 'a', 0})
	f.Add(bytes.Repeat([]byte{10}, 40))
	f.Fuzz(func(t *testing.T, p []byte) { parseMySQLGreeting(p) })
}

func FuzzReadMySQLPacket(f *testing.F) {
	f.Add(buildMySQLGreeting(1, mysqlSalt(20)))
	f.Add([]byte{0xff, 0xff, 0xff, 0})
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, p, err := readMySQLPacket(bytes.NewReader(b), 4096)
		if err == nil && len(p) > 4096 {
			t.Fatal("packet over the limit")
		}
	})
}

func FuzzMongoHeader(f *testing.F) {
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h, 16)
	binary.LittleEndian.PutUint32(h[12:], mongoOpMsg)
	f.Add(h)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		parseMongoHeader(b)
		s := mongoPlainSniffer{}
		m := s.Match(b)
		if len(b) > 0 {
			// deterministic on a prefix: a verdict on a prefix holds for the whole input
			for n := 0; n <= len(b); n++ {
				if p := s.Match(b[:n]); (p == NoMatch && m != NoMatch) || (p == Matched && m != Matched) {
					t.Fatalf("prefix %d said %d, whole said %d", n, p, m)
				}
			}
		}
		// the new sniffers must agree with the built-in ones on exclusivity: TLS and PG never match as Mongo/Redis
		if len(b) >= 2 && b[0] == 0x16 && b[1] == 0x03 && m == Matched {
			t.Fatal("TLS record taken for Mongo")
		}
		if (redisPlainSniffer{}).Match(b) == Matched && len(b) > 0 && b[0] != '*' {
			t.Fatal("redis sniffer matched without '*'")
		}
	})
}

// Hello parsing is shared by the three protocols; keep a fuzz target here for the exact input the MySQL door feeds it
// (the bytes after a valid SSLRequest).
func FuzzHelloAfterMySQLSSLRequest(f *testing.F) {
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 1, 0, 0, 1, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		n, err := HelloLen(b, 16<<10)
		if err == nil && n <= len(b) {
			ParseClientHello(b[:n])
		}
	})
}
