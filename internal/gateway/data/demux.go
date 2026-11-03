package data

import (
	"encoding/binary"
	"errors"
	"strings"
)

// Kind names what a connection speaks, decided from its first bytes. Kinds are strings so that other packages
// (G9, G11, G17) can register new ones together with a Sniffer and a Handler.
type Kind string

// Built-in kinds.
const (
	KindUnknown Kind = ""
	KindTLS     Kind = "tls"    // TLS record (ClientHello): SNI/ALPN decide: capsule/1 tunnel, PostgreSQL direct, SNI route
	KindPGSSL   Kind = "pg-ssl" // PostgreSQL SSLRequest / GSSENCRequest: classic negotiation, TLS follows
	KindHTTP    Kind = "http"   // clear-text HTTP/1.x: routed by Host
	KindSSH     Kind = "ssh"    // clear-text SSH banner (recognised so it can be refused; the SSH-over-TLS path is KindTLS)
)

// Match is the answer of a Sniffer.
type Match int

const (
	NoMatch  Match = iota // these bytes are not this protocol
	NeedMore              // so far compatible, more bytes needed
	Matched               // this protocol
)

// Sniffer decides from the first bytes of a connection. It must be cheap, must not allocate and must be
// deterministic on a prefix: once it answers NoMatch or Matched for a prefix it keeps doing so for longer inputs.
type Sniffer interface {
	Kind() Kind
	Match(first []byte) Match
}

// PostgreSQL protocol request codes (first message: int32 length = 8, int32 code).
const (
	pgSSLRequest  = 80877103
	pgGSSRequest  = 80877104
	pgCancelReq   = 80877102
	pgRequestSize = 8
)

type tlsSniffer struct{}

func (tlsSniffer) Kind() Kind { return KindTLS }
func (tlsSniffer) Match(b []byte) Match {
	if len(b) == 0 {
		return NeedMore
	}
	if b[0] != 0x16 {
		return NoMatch
	}
	if len(b) < 2 {
		return NeedMore
	}
	if b[1] != 0x03 {
		return NoMatch
	}
	return Matched
}

type pgSniffer struct{}

func (pgSniffer) Kind() Kind { return KindPGSSL }
func (pgSniffer) Match(b []byte) Match {
	want := [4]byte{0, 0, 0, 8}
	n := len(b)
	if n > 4 {
		n = 4
	}
	for i := 0; i < n; i++ {
		if b[i] != want[i] {
			return NoMatch
		}
	}
	if len(b) < pgRequestSize {
		return NeedMore
	}
	switch binary.BigEndian.Uint32(b[4:8]) {
	case pgSSLRequest, pgGSSRequest:
		return Matched
	}
	return NoMatch // includes CancelRequest and clear-text startup: not served here
}

var httpMethods = []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "PRI * "}

type httpSniffer struct{}

func (httpSniffer) Kind() Kind { return KindHTTP }
func (httpSniffer) Match(b []byte) Match {
	if len(b) == 0 {
		return NeedMore
	}
	need := false
	for _, m := range httpMethods {
		if len(b) >= len(m) {
			if string(b[:len(m)]) == m {
				return Matched
			}
			continue
		}
		if string(b) == m[:len(b)] {
			need = true
		}
	}
	if need {
		return NeedMore
	}
	return NoMatch
}

type sshSniffer struct{}

func (sshSniffer) Kind() Kind { return KindSSH }
func (sshSniffer) Match(b []byte) Match {
	const p = "SSH-"
	if len(b) >= len(p) {
		if string(b[:len(p)]) == p {
			return Matched
		}
		return NoMatch
	}
	if string(b) == p[:len(b)] {
		return NeedMore
	}
	return NoMatch
}

// BuiltinSniffers returns the default sniffers in priority order.
func BuiltinSniffers() []Sniffer {
	return []Sniffer{tlsSniffer{}, pgSniffer{}, httpSniffer{}, sshSniffer{}}
}

// Classify runs the sniffers over the first bytes. It returns the matched kind; need=true means the bytes read so
// far are a prefix of at least one candidate and more are required; kind "" with need=false means "unknown".
func Classify(sn []Sniffer, first []byte) (kind Kind, need bool) {
	for _, s := range sn {
		switch s.Match(first) {
		case Matched:
			return s.Kind(), false
		case NeedMore:
			need = true
		}
	}
	return KindUnknown, need
}

// Hello is what the gateway needs from a TLS ClientHello. The ClientHello is never answered by the demux: the bytes
// are kept so they can be replayed to the destination (passthrough) or to crypto/tls (termination, tunnel).
type Hello struct {
	SNI         string   // lower case, no trailing dot; "" when absent or invalid
	ALPN        []string // protocol names offered, in order
	Versions    []uint16 // supported_versions extension (empty for TLS <= 1.2 hellos)
	HasECH      bool     // encrypted_client_hello offered (the SNI seen is then the public name)
	LegacyMajor uint8
}

// Offers reports whether the client offered the ALPN protocol p.
func (h *Hello) Offers(p string) bool {
	for _, a := range h.ALPN {
		if a == p {
			return true
		}
	}
	return false
}

// Hello parse errors.
var (
	ErrNotTLS        = errors.New("data: not a TLS handshake record")
	ErrHelloTooLarge = errors.New("data: ClientHello exceeds the limit")
	ErrBadHello      = errors.New("data: malformed ClientHello")
)

// HelloLen inspects the start of a connection that is known to be TLS and returns how many bytes (records included)
// are needed to hold the whole ClientHello handshake message (which may span several records). need > len(b) means
// "read more and call again". It never reads beyond what max permits.
func HelloLen(b []byte, max int) (need int, err error) {
	pos := 0
	hsTotal := -1 // total handshake bytes announced
	hsGot := 0
	for {
		if len(b) < pos+5 {
			return pos + 5, nil
		}
		if b[pos] != 0x16 || b[pos+1] != 0x03 {
			return 0, ErrNotTLS
		}
		rl := int(binary.BigEndian.Uint16(b[pos+3:]))
		if rl == 0 || rl > 1<<14 {
			return 0, ErrBadHello
		}
		if pos+5+rl > max {
			return 0, ErrHelloTooLarge
		}
		if len(b) < pos+5+rl {
			// we still may learn the handshake length from the first record header bytes
			return pos + 5 + rl, nil
		}
		payload := b[pos+5 : pos+5+rl]
		if hsTotal < 0 {
			if len(payload) < 4 {
				return 0, ErrBadHello // handshake header split across records: not supported
			}
			if payload[0] != 1 {
				return 0, ErrBadHello // not a ClientHello
			}
			hsTotal = 4 + (int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3]))
			if hsTotal > max {
				return 0, ErrHelloTooLarge
			}
		}
		hsGot += len(payload)
		pos += 5 + rl
		if hsGot >= hsTotal {
			return pos, nil
		}
		// need another record
	}
}

// ParseClientHello extracts SNI/ALPN from complete record bytes (as sized by HelloLen).
func ParseClientHello(b []byte) (*Hello, error) {
	// Reassemble handshake bytes across records without copying in the common single-record case.
	var hs []byte
	pos := 0
	for pos < len(b) {
		if len(b) < pos+5 || b[pos] != 0x16 || b[pos+1] != 0x03 {
			return nil, ErrNotTLS
		}
		rl := int(binary.BigEndian.Uint16(b[pos+3:]))
		if rl == 0 || pos+5+rl > len(b) {
			return nil, ErrBadHello
		}
		if hs == nil && pos+5+rl == len(b) {
			hs = b[pos+5 : pos+5+rl]
		} else {
			hs = append(hs, b[pos+5:pos+5+rl]...)
		}
		pos += 5 + rl
	}
	if len(hs) < 4 || hs[0] != 1 {
		return nil, ErrBadHello
	}
	n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+n {
		return nil, ErrBadHello
	}
	body := hs[4 : 4+n]
	h := &Hello{LegacyMajor: b[1]}
	r := reader{b: body}
	if !r.skip(2 + 32) { // legacy_version, random
		return nil, ErrBadHello
	}
	if !r.skipVec8() { // session id
		return nil, ErrBadHello
	}
	cs, ok := r.vec16()
	if !ok || len(cs) < 2 || len(cs)%2 != 0 {
		return nil, ErrBadHello
	}
	if !r.skipVec8() { // compression methods
		return nil, ErrBadHello
	}
	if r.len() == 0 {
		return h, nil // no extensions (TLS <= 1.2 without SNI)
	}
	exts, ok := r.vec16()
	if !ok || r.len() != 0 {
		return nil, ErrBadHello
	}
	er := reader{b: exts}
	for er.len() > 0 {
		t, ok1 := er.u16()
		d, ok2 := er.vec16()
		if !ok1 || !ok2 {
			return nil, ErrBadHello
		}
		switch t {
		case 0x0000: // server_name
			if h.SNI != "" {
				continue
			}
			l := reader{b: d}
			list, ok := l.vec16()
			if !ok || l.len() != 0 {
				return nil, ErrBadHello
			}
			lr := reader{b: list}
			for lr.len() > 0 {
				nt, ok1 := lr.u8()
				name, ok2 := lr.vec16()
				if !ok1 || !ok2 {
					return nil, ErrBadHello
				}
				if nt == 0 && h.SNI == "" {
					h.SNI = normalizeSNI(name)
				}
			}
		case 0x0010: // ALPN
			l := reader{b: d}
			list, ok := l.vec16()
			if !ok || l.len() != 0 {
				return nil, ErrBadHello
			}
			lr := reader{b: list}
			for lr.len() > 0 {
				p, ok := lr.vec8()
				if !ok || len(p) == 0 {
					return nil, ErrBadHello
				}
				if len(h.ALPN) < 32 {
					h.ALPN = append(h.ALPN, string(p))
				}
			}
		case 0x002b: // supported_versions (client form: u8 list length)
			l := reader{b: d}
			list, ok := l.vec8()
			if !ok || len(list)%2 != 0 {
				return nil, ErrBadHello
			}
			for i := 0; i+1 < len(list) && len(h.Versions) < 32; i += 2 {
				h.Versions = append(h.Versions, binary.BigEndian.Uint16(list[i:]))
			}
		case 0xfe0d:
			h.HasECH = true
		}
	}
	return h, nil
}

// normalizeSNI lower-cases and validates a host name; it returns "" for anything that is not a plausible DNS name.
func normalizeSNI(b []byte) string {
	if len(b) == 0 || len(b) > 253 {
		return ""
	}
	if b[len(b)-1] == '.' {
		b = b[:len(b)-1]
		if len(b) == 0 {
			return ""
		}
	}
	out := make([]byte, len(b))
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return ""
		}
		out[i] = c
	}
	return string(out)
}

// HostFromHTTPHead extracts the Host header value (without port) from a clear-text HTTP/1.x request head.
// head may be partial; complete reports whether the blank line ending the headers was seen.
func HostFromHTTPHead(head []byte) (host string, complete bool) {
	s := string(head)
	end := strings.Index(s, "\r\n\r\n")
	if end >= 0 {
		complete = true
		s = s[:end]
	}
	lines := strings.Split(s, "\r\n")
	if !complete { // the last element is a line that may still be arriving: never trust it
		lines = lines[:len(lines)-1]
	}
	for i, ln := range lines {
		if i == 0 {
			continue
		}
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "host") {
			v = strings.TrimSpace(v)
			if strings.HasPrefix(v, "[") { // [v6]:port
				if j := strings.Index(v, "]"); j > 0 {
					v = v[1:j]
				}
			} else if j := strings.LastIndexByte(v, ':'); j >= 0 {
				v = v[:j]
			}
			return normalizeSNIString(v), complete
		}
	}
	return "", complete
}

func normalizeSNIString(s string) string { return normalizeSNI([]byte(s)) }

type reader struct{ b []byte }

func (r *reader) len() int { return len(r.b) }
func (r *reader) skip(n int) bool {
	if len(r.b) < n {
		return false
	}
	r.b = r.b[n:]
	return true
}
func (r *reader) u8() (uint8, bool) {
	if len(r.b) < 1 {
		return 0, false
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v, true
}
func (r *reader) u16() (uint16, bool) {
	if len(r.b) < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.b)
	r.b = r.b[2:]
	return v, true
}
func (r *reader) vec8() ([]byte, bool) {
	n, ok := r.u8()
	if !ok || len(r.b) < int(n) {
		return nil, false
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v, true
}
func (r *reader) skipVec8() bool { _, ok := r.vec8(); return ok }
func (r *reader) vec16() ([]byte, bool) {
	n, ok := r.u16()
	if !ok || len(r.b) < int(n) {
		return nil, false
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v, true
}
