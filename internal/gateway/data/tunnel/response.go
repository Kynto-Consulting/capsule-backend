package tunnel

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Response status classes (PROTOCOL.md section 7).
const (
	StatusOK            = 0
	StatusBadRequest    = 1
	StatusNotAuthorized = 2
	StatusIPDenied      = 3
	StatusUnavailable   = 4
	StatusQuota         = 5
	StatusBusy          = 6
)

// Response codes used by the gateway (status 2..6) and size limits.
const (
	CodeNotAuthorized = 0x0201
	CodeTokenExpired  = 0x0202
	CodeReplay        = 0x0203
	CodeIPDenied      = 0x0301
	CodeDestDown      = 0x0401
	CodeDestTimeout   = 0x0402
	CodeQuotaProject  = 0x0501
	CodeQuotaIP       = 0x0502
	CodeQuotaRate     = 0x0503
	CodeQuotaUDP      = 0x0504
	CodeDraining      = 0x0601
	CodeControlDown   = 0x0602
	CodeInternal      = 0x0603

	MaxMsgLen        = 120
	MaxExtLen        = 256
	MsgNotAuthorized = "not authorized"
)

// ClientAddr is TLV 0x04: the address the gateway sees for the client.
type ClientAddr struct {
	Addr netip.Addr
	Port uint16
}

// Response is a decoded (or to be encoded) CAPR message.
type Response struct {
	Version     byte
	Status      byte
	Code        uint16
	Msg         string
	MaxVersion  *byte
	RetryAfter  *uint16
	SessionID   []byte // 8 bytes
	ClientAddr  *ClientAddr
	MaxDatagram *uint16
	IdleTimeout *uint16
}

// ResponseError names the decoder failures of PROTOCOL.md section 6 (same names as the test vectors).
type ResponseError string

func (e ResponseError) Error() string { return "capsule/1 response: " + string(e) }

// Response decoder errors.
const (
	ErrTruncated  ResponseError = "truncated"
	ErrBadMagic   ResponseError = "bad_magic"
	ErrBadVersion ResponseError = "bad_version"
	ErrMsgTooLong ResponseError = "msg_too_long"
	ErrBadMsg     ResponseError = "bad_msg"
	ErrExtTooLong ResponseError = "ext_too_long"
	ErrBadExt     ResponseError = "bad_ext"
)

// ErrIncompleteResponse means more bytes are needed.
var ErrIncompleteResponse = errors.New("capsule/1 response: incomplete")

// EncodeResponse builds a CAPR. msg is cut to 120 visible ASCII bytes.
func EncodeResponse(r *Response) []byte {
	ver := r.Version
	if ver == 0 {
		ver = Version
	}
	msg := make([]byte, 0, len(r.Msg))
	for i := 0; i < len(r.Msg) && len(msg) < MaxMsgLen; i++ {
		if c := r.Msg[i]; c >= 0x20 && c <= 0x7e {
			msg = append(msg, c)
		}
	}
	var ext []byte
	if r.MaxVersion != nil {
		ext = append(ext, 0x01, 1, *r.MaxVersion)
	}
	if r.RetryAfter != nil {
		ext = append(ext, 0x02, 2)
		ext = binary.BigEndian.AppendUint16(ext, *r.RetryAfter)
	}
	if len(r.SessionID) == 8 {
		ext = append(ext, 0x03, 8)
		ext = append(ext, r.SessionID...)
	}
	if r.ClientAddr != nil && r.ClientAddr.Addr.IsValid() {
		a := r.ClientAddr.Addr.Unmap()
		if a.Is4() {
			b := a.As4()
			ext = append(ext, 0x04, 7, 4)
			ext = append(ext, b[:]...)
		} else {
			b := a.As16()
			ext = append(ext, 0x04, 19, 6)
			ext = append(ext, b[:]...)
		}
		ext = binary.BigEndian.AppendUint16(ext, r.ClientAddr.Port)
	}
	if r.MaxDatagram != nil {
		ext = append(ext, 0x05, 2)
		ext = binary.BigEndian.AppendUint16(ext, *r.MaxDatagram)
	}
	if r.IdleTimeout != nil {
		ext = append(ext, 0x06, 2)
		ext = binary.BigEndian.AppendUint16(ext, *r.IdleTimeout)
	}
	out := make([]byte, 0, 11+len(msg)+len(ext))
	out = append(out, 'C', 'A', 'P', 'R', ver, r.Status)
	out = binary.BigEndian.AppendUint16(out, r.Code)
	out = append(out, byte(len(msg)))
	out = append(out, msg...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(ext)))
	return append(out, ext...)
}

// DecodeResponse decodes a CAPR following PROTOCOL.md section 6. eof tells whether the stream ended.
func DecodeResponse(b []byte, eof bool) (*Response, int, error) {
	need := func() (*Response, int, error) {
		if eof {
			return nil, 0, ErrTruncated
		}
		return nil, 0, ErrIncompleteResponse
	}
	if len(b) < 9 {
		return need()
	}
	if string(b[:4]) != "CAPR" {
		return nil, 0, ErrBadMagic
	}
	if b[4] == 0 {
		return nil, 0, ErrBadVersion
	}
	ml := int(b[8])
	if ml > MaxMsgLen {
		return nil, 0, ErrMsgTooLong
	}
	if len(b) < 9+ml+2 {
		return need()
	}
	for _, c := range b[9 : 9+ml] {
		if c < 0x20 || c > 0x7e {
			return nil, 0, ErrBadMsg
		}
	}
	el := int(binary.BigEndian.Uint16(b[9+ml:]))
	if el > MaxExtLen {
		return nil, 0, ErrExtTooLong
	}
	total := 9 + ml + 2 + el
	if len(b) < total {
		return need()
	}
	r := &Response{Version: b[4], Status: b[5], Code: binary.BigEndian.Uint16(b[6:8]), Msg: string(b[9 : 9+ml])}
	ext := b[9+ml+2 : total]
	var seen [7]bool
	for len(ext) > 0 {
		if len(ext) < 2 || 2+int(ext[1]) > len(ext) {
			return nil, 0, ErrBadExt
		}
		t, l := ext[0], int(ext[1])
		v := ext[2 : 2+l]
		ext = ext[2+l:]
		if t >= 0x01 && t <= 0x06 {
			if seen[t] {
				return nil, 0, ErrBadExt
			}
			seen[t] = true
		}
		switch t {
		case 0x01:
			if l != 1 {
				return nil, 0, ErrBadExt
			}
			x := v[0]
			r.MaxVersion = &x
		case 0x02:
			if l != 2 {
				return nil, 0, ErrBadExt
			}
			x := binary.BigEndian.Uint16(v)
			r.RetryAfter = &x
		case 0x03:
			if l != 8 {
				return nil, 0, ErrBadExt
			}
			r.SessionID = append([]byte(nil), v...)
		case 0x04:
			switch {
			case l == 7 && v[0] == 4:
				a, _ := netip.AddrFromSlice(v[1:5])
				r.ClientAddr = &ClientAddr{Addr: a, Port: binary.BigEndian.Uint16(v[5:])}
			case l == 19 && v[0] == 6:
				a, _ := netip.AddrFromSlice(v[1:17])
				r.ClientAddr = &ClientAddr{Addr: a, Port: binary.BigEndian.Uint16(v[17:])}
			default:
				return nil, 0, ErrBadExt
			}
		case 0x05:
			if l != 2 {
				return nil, 0, ErrBadExt
			}
			x := binary.BigEndian.Uint16(v)
			r.MaxDatagram = &x
		case 0x06:
			if l != 2 {
				return nil, 0, ErrBadExt
			}
			x := binary.BigEndian.Uint16(v)
			r.IdleTimeout = &x
		}
	}
	return r, total, nil
}
