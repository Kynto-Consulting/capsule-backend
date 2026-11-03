package tunnel

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// The normative vectors live next to the specification, outside the Go module.
const vectorDir = "../../../../../docs/gateway/testvectors"

func loadVectors(t testing.TB, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatalf("test vectors not found (%v): they ship with docs/gateway/testvectors", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

type vec struct {
	Name      string          `json:"name"`
	Hex       string          `json:"hex"`
	EOF       bool            `json:"eof"`
	Canonical bool            `json:"canonical"`
	Expect    json.RawMessage `json:"expect"`
}

type expect struct {
	Incomplete bool            `json:"incomplete"`
	OK         *bool           `json:"ok"`
	Consumed   int             `json:"consumed"`
	Status     byte            `json:"status"`
	Code       string          `json:"code"`
	ErrName    string          `json:"error"`
	Fields     json.RawMessage `json:"fields"`
}

type reqFields struct {
	Transport byte   `json:"transport"`
	Flags     byte   `json:"flags"`
	Project   string `json:"project"`
	Service   string `json:"service"`
	AuthType  byte   `json:"auth_type"`
	Auth      string `json:"auth"`
	Ignored   int    `json:"ignored_tlvs"`
	NonceHex  string `json:"nonce_hex"`
	ClientID  string `json:"client_id"`
	Padding   int    `json:"padding"`
}

func TestRequestVectors(t *testing.T) {
	var f struct {
		Vectors []vec `json:"vectors"`
	}
	loadVectors(t, "request.json", &f)
	if len(f.Vectors) < 60 {
		t.Fatalf("too few vectors: %d", len(f.Vectors))
	}
	canon := 0
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(v.Hex)
			if err != nil {
				t.Fatal(err)
			}
			var e expect
			if err := json.Unmarshal(v.Expect, &e); err != nil {
				t.Fatal(err)
			}
			req, consumed, derr := DecodeRequest(raw, v.EOF)
			switch {
			case e.Incomplete:
				if !errors.Is(derr, ErrIncomplete) {
					t.Fatalf("want incomplete, got %v", derr)
				}
			case e.OK != nil && *e.OK:
				if derr != nil {
					t.Fatalf("unexpected error %v", derr)
				}
				var fl reqFields
				if err := json.Unmarshal(e.Fields, &fl); err != nil {
					t.Fatal(err)
				}
				if consumed != e.Consumed {
					t.Fatalf("consumed %d want %d", consumed, e.Consumed)
				}
				if req.Transport != fl.Transport || req.Flags != fl.Flags || req.Project != fl.Project || req.Service != fl.Service ||
					req.AuthType != fl.AuthType || req.Auth != fl.Auth || req.IgnoredTLVs != fl.Ignored ||
					req.ClientID != fl.ClientID || hex.EncodeToString(req.Nonce) != fl.NonceHex {
					t.Fatalf("fields mismatch: %+v vs %+v", req, fl)
				}
				// optimistic data after the header must not change the result
				req2, c2, err2 := DecodeRequest(append(append([]byte(nil), raw...), "trailing application data"...), false)
				if err2 != nil || c2 != consumed || req2.Auth != req.Auth || req2.Project != req.Project {
					t.Fatalf("trailing bytes changed the result: %v %d", err2, c2)
				}
				if v.Canonical {
					canon++
					enc, err := EncodeRequest(&Request{Flags: fl.Flags, Transport: fl.Transport, Project: fl.Project, Service: fl.Service,
						AuthType: fl.AuthType, Auth: fl.Auth, Nonce: mustHex(fl.NonceHex), ClientID: fl.ClientID, Padding: fl.Padding})
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(enc, raw) {
						t.Fatalf("canonical encoding differs:\n got %x\nwant %x", enc, raw)
					}
				}
			default:
				var te *Error
				if !errors.As(derr, &te) {
					t.Fatalf("want protocol error, got %v (req %+v)", derr, req)
				}
				var code uint16
				fmt.Sscanf(e.Code, "0x%x", &code)
				if te.Status != e.Status || te.Code != code {
					t.Fatalf("got status %d code 0x%04x, want %d %s", te.Status, te.Code, e.Status, e.Code)
				}
			}
		})
	}
	if canon < 10 {
		t.Fatalf("only %d canonical vectors encoded", canon)
	}
}

func mustHex(s string) []byte {
	if s == "" {
		return nil
	}
	b, _ := hex.DecodeString(s)
	return b
}

func TestResponseVectors(t *testing.T) {
	var f struct {
		Vectors []vec `json:"vectors"`
	}
	loadVectors(t, "response.json", &f)
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			raw, _ := hex.DecodeString(v.Hex)
			var e expect
			if err := json.Unmarshal(v.Expect, &e); err != nil {
				t.Fatal(err)
			}
			r, consumed, err := DecodeResponse(raw, v.EOF)
			switch {
			case e.Incomplete:
				if !errors.Is(err, ErrIncompleteResponse) {
					t.Fatalf("want incomplete, got %v", err)
				}
			case e.OK != nil && *e.OK:
				if err != nil {
					t.Fatal(err)
				}
				var fl struct {
					Version byte   `json:"version"`
					Status  byte   `json:"status"`
					Code    uint16 `json:"code"`
					Msg     string `json:"msg"`
					TLVs    struct {
						MaxVersion *byte   `json:"max_version"`
						RetryAfter *uint16 `json:"retry_after"`
						SessionHex string  `json:"session_id_hex"`
						ClientAddr *struct {
							IP   string `json:"ip"`
							Port uint16 `json:"port"`
						} `json:"client_addr"`
						MaxDatagram *uint16 `json:"max_datagram"`
						Idle        *uint16 `json:"idle_timeout"`
					} `json:"tlvs"`
				}
				if err := json.Unmarshal(e.Fields, &fl); err != nil {
					t.Fatal(err)
				}
				if consumed != e.Consumed || r.Version != fl.Version || r.Status != fl.Status || r.Code != fl.Code || r.Msg != fl.Msg {
					t.Fatalf("mismatch %+v consumed=%d", r, consumed)
				}
				if hex.EncodeToString(r.SessionID) != fl.TLVs.SessionHex {
					t.Fatal("session id")
				}
				eqp := func(a, b *uint16) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }
				if !eqp(r.RetryAfter, fl.TLVs.RetryAfter) || !eqp(r.MaxDatagram, fl.TLVs.MaxDatagram) || !eqp(r.IdleTimeout, fl.TLVs.Idle) {
					t.Fatal("tlv mismatch")
				}
				if (r.MaxVersion == nil) != (fl.TLVs.MaxVersion == nil) || (r.MaxVersion != nil && *r.MaxVersion != *fl.TLVs.MaxVersion) {
					t.Fatal("max_version")
				}
				if (r.ClientAddr == nil) != (fl.TLVs.ClientAddr == nil) {
					t.Fatal("client_addr presence")
				}
				if r.ClientAddr != nil && (r.ClientAddr.Addr != netip.MustParseAddr(fl.TLVs.ClientAddr.IP) || r.ClientAddr.Port != fl.TLVs.ClientAddr.Port) {
					t.Fatal("client_addr")
				}
				if v.Canonical {
					if enc := EncodeResponse(r); !bytes.Equal(enc, raw[:consumed]) {
						t.Fatalf("canonical encoding differs:\n got %x\nwant %x", enc, raw[:consumed])
					}
				}
			default:
				if string(ResponseError(e.ErrName)) == "" || !errors.Is(err, ResponseError(e.ErrName)) {
					t.Fatalf("want %s got %v", e.ErrName, err)
				}
			}
		})
	}
}

func TestUDPFrameVectors(t *testing.T) {
	var f struct {
		Vectors []struct {
			Name   string `json:"name"`
			Hex    string `json:"hex"`
			Expect struct {
				Datagrams  []string `json:"datagrams"`
				Keepalives int      `json:"keepalives"`
				Pending    int      `json:"pending"`
				Error      string   `json:"error"`
			} `json:"expect"`
		} `json:"vectors"`
	}
	loadVectors(t, "udp_frames.json", &f)
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			raw, _ := hex.DecodeString(v.Hex)
			d, k, p, err := SplitFrames(raw)
			if v.Expect.Error != "" {
				if !errors.Is(err, ErrFrameTooLarge) {
					t.Fatalf("want frame_too_large, got %v", err)
				}
				return
			}
			if err != nil || k != v.Expect.Keepalives || p != v.Expect.Pending || len(d) != len(v.Expect.Datagrams) {
				t.Fatalf("got d=%d k=%d p=%d err=%v", len(d), k, p, err)
			}
			for i := range d {
				if hex.EncodeToString(d[i]) != v.Expect.Datagrams[i] {
					t.Fatalf("datagram %d differs", i)
				}
			}
			// re-encoding round trip
			var out []byte
			for _, x := range d {
				out = AppendFrame(out, x)
			}
			if len(d) > 0 && k == 0 && p == 0 && !bytes.Equal(out, raw) {
				t.Fatal("round trip")
			}
		})
	}
}

func TestIPAllowlistVectors(t *testing.T) {
	var f struct {
		Vectors []struct {
			Name    string   `json:"name"`
			CIDRs   []string `json:"cidrs"`
			IP      string   `json:"ip"`
			Allowed bool     `json:"allowed"`
		} `json:"vectors"`
	}
	loadVectors(t, "ip_allowlist.json", &f)
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			list := []netip.Prefix{} // explicit empty list denies everything
			for _, c := range v.CIDRs {
				list = append(list, netip.MustParsePrefix(c))
			}
			if got := AllowedByList(list, netip.MustParseAddr(v.IP)); got != v.Allowed {
				t.Fatalf("got %v want %v", got, v.Allowed)
			}
		})
	}
	if !AllowedByList(nil, netip.MustParseAddr("203.0.113.5")) {
		t.Fatal("nil list must not restrict")
	}
}

func FuzzDecodeRequest(f *testing.F) {
	var vf struct {
		Vectors []vec `json:"vectors"`
	}
	b, err := os.ReadFile(filepath.Join(vectorDir, "request.json"))
	if err == nil && json.Unmarshal(b, &vf) == nil {
		for _, v := range vf.Vectors {
			raw, _ := hex.DecodeString(v.Hex)
			f.Add(raw, v.EOF)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte, eof bool) {
		req, n, err := DecodeRequest(b, eof)
		switch {
		case err == nil:
			if n < MinHdrLen || n > MaxHdrLen || n > len(b) || req == nil {
				t.Fatalf("bad success n=%d len=%d", n, len(b))
			}
			// a valid header must re-encode to the same bytes unless it carried ignorable TLVs
			if req.IgnoredTLVs == 0 {
				enc, e2 := EncodeRequest(req)
				if e2 != nil || !bytes.Equal(enc, b[:n]) {
					t.Fatalf("re-encode mismatch: %v", e2)
				}
			}
		case errors.Is(err, ErrIncomplete):
			if eof {
				t.Fatal("incomplete at EOF")
			}
		default:
			var te *Error
			if !errors.As(err, &te) || te.Status != 1 || te.Code < 0x0101 || te.Code > 0x010B {
				t.Fatalf("error outside the table: %v", err)
			}
		}
	})
}

func FuzzDecodeResponse(f *testing.F) {
	var vf struct {
		Vectors []vec `json:"vectors"`
	}
	b, err := os.ReadFile(filepath.Join(vectorDir, "response.json"))
	if err == nil && json.Unmarshal(b, &vf) == nil {
		for _, v := range vf.Vectors {
			raw, _ := hex.DecodeString(v.Hex)
			f.Add(raw, v.EOF)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte, eof bool) {
		r, n, err := DecodeResponse(b, eof)
		if err == nil && (r == nil || n > len(b) || n < 11) {
			t.Fatalf("bad success n=%d", n)
		}
	})
}

func FuzzSplitFrames(f *testing.F) {
	f.Add([]byte{0, 3, 'a', 'b', 'c', 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		d, _, p, err := SplitFrames(b)
		if err == nil {
			total := p
			for _, x := range d {
				if len(x) == 0 || len(x) > MaxDatagram {
					t.Fatal("bad datagram")
				}
				total += len(x) + 2
			}
			if total > len(b) {
				t.Fatal("overcount")
			}
		}
	})
}
