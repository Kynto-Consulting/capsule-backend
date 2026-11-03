// Package tunnel implements the wire codec of the capsule/1 tunnel protocol (docs/gateway/PROTOCOL.md):
// the CAP1 request header, the CAPR response, the UDP-over-stream frames and the source-IP canonicalisation.
// It has no I/O and no dependencies beyond the standard library, so the gateway and the Go client can share it.
package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Protocol constants (PROTOCOL.md sections 5 and 9.3).
const (
	Version       = 1
	MinHdrLen     = 17
	MaxHdrLen     = 1024
	MaxAuthLen    = 512
	MinAuthLen    = 8
	MaxNameLen    = 63
	MaxNonceLen   = 16
	MaxClientID   = 64
	fixedPrefix   = 9 // magic(4) version(1) flags(1) hdr_len(2) transport(1)
	flagWantProxy = 0x01
)

// Transport values of the request header.
const (
	TransportTCP     = 1
	TransportUDPFlow = 2
	TransportUDPQUIC = 3
)

// Auth types of the request header.
const (
	AuthCap = 1 // cap_
	AuthCgt = 2 // cgt_
	AuthCgc = 3 // cgc_
	AuthCgs = 4 // cgs_
)

// AuthPrefix returns the mandatory token prefix for an auth type ("" when unknown).
func AuthPrefix(t byte) string {
	switch t {
	case AuthCap:
		return "cap_"
	case AuthCgt:
		return "cgt_"
	case AuthCgc:
		return "cgc_"
	case AuthCgs:
		return "cgs_"
	}
	return ""
}

// Request is a decoded (or to be encoded) CAP1 header.
type Request struct {
	Flags       byte
	Transport   byte
	Project     string
	Service     string
	AuthType    byte
	Auth        string // full token, never to be logged
	Nonce       []byte // optional, 16 bytes
	ClientID    string // optional
	Padding     int    // encode only: number of 0x00 bytes in a 0x80 TLV
	IgnoredTLVs int    // decode only: count of ignorable TLVs (type >= 0x80) seen
	HdrLen      int    // decode only
}

// WantProxyInfo reports flag bit0.
func (r *Request) WantProxyInfo() bool { return r.Flags&flagWantProxy != 0 }

// Error is a protocol-level failure carrying the CAPR status and code that must be sent (PROTOCOL.md section 7).
type Error struct {
	Status byte
	Code   uint16
}

func (e *Error) Error() string {
	return fmt.Sprintf("capsule/1: status %d code 0x%04x", e.Status, e.Code)
}

// Request header error codes (status 1, PROTOCOL.md section 7).
const (
	CodeUnsupportedVersion = 0x0101
	CodeBadMagic           = 0x0102
	CodeBadHdrLen          = 0x0103
	CodeBadFlags           = 0x0104
	CodeBadName            = 0x0105
	CodeBadAuth            = 0x0106
	CodeBadTLV             = 0x0107
	CodeUnknownCritical    = 0x0108
	CodeBadTransport       = 0x0109
	CodeTruncated          = 0x010A
	CodeInconsistent       = 0x010B
)

func reqErr(code uint16) *Error { return &Error{Status: 1, Code: code} }

// ErrIncomplete means more bytes are needed (and the stream is still open).
var ErrIncomplete = errors.New("capsule/1: incomplete header")

// IsName reports whether s matches ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ (section 1.6).
func IsName(s string) bool {
	if len(s) < 1 || len(s) > MaxNameLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(s)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func isTokenChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}

func isClientIDChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '.' || c == '_' || c == '/' || c == '+' || c == '-'
}

// DecodeRequest decodes a CAP1 header following the normative algorithm of PROTOCOL.md section 5.
// b holds the bytes received so far; eof tells whether the stream ended after them.
// Results: (req, consumed, nil) on success (consumed = hdr_len; later bytes are optimistic application data);
// ErrIncomplete when more bytes are needed; *Error otherwise. It never allocates proportionally to declared lengths
// (hdr_len is bounded to 1024 before anything is copied) and never panics.
func DecodeRequest(b []byte, eof bool) (*Request, int, error) {
	if len(b) < 8 {
		if eof {
			return nil, 0, reqErr(CodeTruncated)
		}
		return nil, 0, ErrIncomplete
	}
	if string(b[:4]) != "CAP1" {
		return nil, 0, reqErr(CodeBadMagic)
	}
	if b[4] != Version {
		return nil, 0, reqErr(CodeUnsupportedVersion)
	}
	hl := int(binary.BigEndian.Uint16(b[6:8]))
	if hl < MinHdrLen || hl > MaxHdrLen {
		return nil, 0, reqErr(CodeBadHdrLen)
	}
	if len(b) < hl {
		if eof {
			return nil, 0, reqErr(CodeTruncated)
		}
		return nil, 0, ErrIncomplete
	}
	h := b[:hl]
	r := &Request{Flags: h[5], HdrLen: hl}
	if r.Flags&^flagWantProxy != 0 {
		return nil, 0, reqErr(CodeBadFlags)
	}
	r.Transport = h[8]
	if r.Transport < TransportTCP || r.Transport > TransportUDPQUIC {
		return nil, 0, reqErr(CodeBadTransport)
	}
	pos := fixedPrefix
	readName := func() (string, error) {
		if pos >= hl {
			return "", reqErr(CodeInconsistent)
		}
		n := int(h[pos])
		pos++
		if n < 1 || n > MaxNameLen {
			return "", reqErr(CodeBadName)
		}
		if pos+n > hl {
			return "", reqErr(CodeInconsistent)
		}
		s := string(h[pos : pos+n])
		pos += n
		if !IsName(s) {
			return "", reqErr(CodeBadName)
		}
		return s, nil
	}
	var err error
	if r.Project, err = readName(); err != nil {
		return nil, 0, err
	}
	if r.Service, err = readName(); err != nil {
		return nil, 0, err
	}
	if pos >= hl {
		return nil, 0, reqErr(CodeInconsistent)
	}
	r.AuthType = h[pos]
	pos++
	if r.AuthType < AuthCap || r.AuthType > AuthCgs {
		return nil, 0, reqErr(CodeBadAuth)
	}
	if pos+2 > hl {
		return nil, 0, reqErr(CodeInconsistent)
	}
	al := int(binary.BigEndian.Uint16(h[pos:]))
	pos += 2
	if al < MinAuthLen || al > MaxAuthLen {
		return nil, 0, reqErr(CodeBadAuth)
	}
	if pos+al > hl {
		return nil, 0, reqErr(CodeInconsistent)
	}
	tok := h[pos : pos+al]
	pos += al
	pfx := AuthPrefix(r.AuthType)
	if string(tok[:len(pfx)]) != pfx {
		return nil, 0, reqErr(CodeBadAuth)
	}
	for _, c := range tok {
		if !isTokenChar(c) {
			return nil, 0, reqErr(CodeBadAuth)
		}
	}
	r.Auth = string(tok)
	var seenNonce, seenCID bool
	for pos < hl {
		if pos+2 > hl {
			return nil, 0, reqErr(CodeBadTLV)
		}
		t, l := h[pos], int(h[pos+1])
		pos += 2
		if pos+l > hl {
			return nil, 0, reqErr(CodeBadTLV)
		}
		v := h[pos : pos+l]
		pos += l
		switch {
		case t == 0x01:
			if seenNonce || l != MaxNonceLen {
				return nil, 0, reqErr(CodeBadTLV)
			}
			seenNonce = true
			r.Nonce = append([]byte(nil), v...)
		case t == 0x02:
			if seenCID || l < 1 || l > MaxClientID {
				return nil, 0, reqErr(CodeBadTLV)
			}
			for _, c := range v {
				if !isClientIDChar(c) {
					return nil, 0, reqErr(CodeBadTLV)
				}
			}
			seenCID = true
			r.ClientID = string(v)
		case t >= 0x80:
			r.IgnoredTLVs++
		default:
			return nil, 0, reqErr(CodeUnknownCritical)
		}
	}
	return r, hl, nil
}

// EncodeRequest builds the canonical CAP1 header (TLV order: nonce, client_id, padding).
func EncodeRequest(r *Request) ([]byte, error) {
	if !IsName(r.Project) || !IsName(r.Service) {
		return nil, errors.New("capsule/1: invalid project or service name")
	}
	pfx := AuthPrefix(r.AuthType)
	if pfx == "" || len(r.Auth) < MinAuthLen || len(r.Auth) > MaxAuthLen || r.Auth[:len(pfx)] != pfx {
		return nil, errors.New("capsule/1: invalid token")
	}
	var tl []byte
	if r.Nonce != nil {
		if len(r.Nonce) != MaxNonceLen {
			return nil, errors.New("capsule/1: nonce must be 16 bytes")
		}
		tl = append(tl, 0x01, MaxNonceLen)
		tl = append(tl, r.Nonce...)
	}
	if r.ClientID != "" {
		if len(r.ClientID) > MaxClientID {
			return nil, errors.New("capsule/1: client id too long")
		}
		tl = append(tl, 0x02, byte(len(r.ClientID)))
		tl = append(tl, r.ClientID...)
	}
	if r.Padding > 0 {
		if r.Padding > 255 {
			return nil, errors.New("capsule/1: padding too long")
		}
		tl = append(tl, 0x80, byte(r.Padding))
		tl = append(tl, make([]byte, r.Padding)...)
	}
	total := fixedPrefix + 1 + len(r.Project) + 1 + len(r.Service) + 1 + 2 + len(r.Auth) + len(tl)
	if total > MaxHdrLen {
		return nil, errors.New("capsule/1: header too large")
	}
	out := make([]byte, 0, total)
	out = append(out, 'C', 'A', 'P', '1', Version, r.Flags)
	out = binary.BigEndian.AppendUint16(out, uint16(total))
	out = append(out, r.Transport, byte(len(r.Project)))
	out = append(out, r.Project...)
	out = append(out, byte(len(r.Service)))
	out = append(out, r.Service...)
	out = append(out, r.AuthType)
	out = binary.BigEndian.AppendUint16(out, uint16(len(r.Auth)))
	out = append(out, r.Auth...)
	out = append(out, tl...)
	return out, nil
}
