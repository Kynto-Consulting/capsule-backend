package tunnel

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// MaxDatagram is the fixed upper bound of a UDP-over-stream frame (PROTOCOL.md section 10.3).
const MaxDatagram = 2048

// ErrFrameTooLarge is returned when a frame announces more than MaxDatagram bytes.
var ErrFrameTooLarge = errors.New("capsule/1: frame_too_large")

// SplitFrames extracts complete len16 frames from b. It returns the datagrams (slices into b), the number of
// keepalives (len 0) and how many bytes of an incomplete trailing frame are pending (header or body bytes present).
// The data plane serves transport 2 with a streaming reader (udp_session.go); this block codec is its reference in tests.
func SplitFrames(b []byte) (datagrams [][]byte, keepalives, pending int, err error) {
	for len(b) > 0 {
		if len(b) < 2 {
			return datagrams, keepalives, len(b), nil
		}
		n := int(binary.BigEndian.Uint16(b))
		if n > MaxDatagram {
			return datagrams, keepalives, 0, ErrFrameTooLarge
		}
		if n == 0 {
			keepalives++
			b = b[2:]
			continue
		}
		if len(b) < 2+n {
			return datagrams, keepalives, len(b), nil
		}
		datagrams = append(datagrams, b[2:2+n])
		b = b[2+n:]
	}
	return datagrams, keepalives, 0, nil
}

// AppendFrame appends one len16 frame (an empty payload is a keepalive).
func AppendFrame(dst, payload []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(payload)))
	return append(dst, payload...)
}

// CanonicalIP normalises a source address: IPv4-mapped IPv6 becomes IPv4 and any zone is dropped (PROTOCOL.md 12.1).
func CanonicalIP(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

// AllowedByList evaluates a project IP list for a source address. A nil list means "no restriction";
// an explicit empty (non-nil) list denies everything. Matching is per family after canonicalising the source.
func AllowedByList(cidrs []netip.Prefix, ip netip.Addr) bool {
	if cidrs == nil {
		return true
	}
	ip = CanonicalIP(ip)
	for _, p := range cidrs {
		pa := p.Addr()
		if pa.Is4In6() { // a ::ffff:0:0/96 entry is not considered (section 12.1)
			continue
		}
		if pa.Is4() != ip.Is4() {
			continue
		}
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
