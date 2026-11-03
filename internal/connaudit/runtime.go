package connaudit

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Conn is one TCP socket read from /proc/net/tcp or /proc/net/tcp6.
type Conn struct {
	Local, Remote         netip.Addr
	LocalPort, RemotePort int
	State                 string // hex state: 01 ESTABLISHED, 0A LISTEN
}

// ParseProcNet parses /proc/net/tcp (v6=false) or /proc/net/tcp6 (v6=true).
// Addresses are the kernel's hex form: for IPv4 one little-endian 32-bit word
// (127.0.0.1 -> 0100007F), for IPv6 four little-endian 32-bit words. Malformed
// lines are skipped.
func ParseProcNet(r io.Reader, v6 bool) []Conn {
	var out []Conn
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || !strings.HasSuffix(f[0], ":") {
			continue // header or garbage
		}
		la, lp, ok1 := parseProcAddr(f[1], v6)
		ra, rp, ok2 := parseProcAddr(f[2], v6)
		if !ok1 || !ok2 {
			continue
		}
		out = append(out, Conn{Local: la, LocalPort: lp, Remote: ra, RemotePort: rp, State: strings.ToUpper(f[3])})
	}
	return out
}

func parseProcAddr(s string, v6 bool) (netip.Addr, int, bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	raw, err := hex.DecodeString(s[:i])
	if err != nil {
		return netip.Addr{}, 0, false
	}
	switch {
	case !v6 && len(raw) == 4:
		return netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]}), int(port), true
	case v6 && len(raw) == 16:
		var b [16]byte
		for w := 0; w < 4; w++ { // each 32-bit word is stored little-endian
			for k := 0; k < 4; k++ {
				b[w*4+k] = raw[w*4+3-k]
			}
		}
		return netip.AddrFrom16(b).Unmap(), int(port), true
	}
	return netip.Addr{}, 0, false
}

// Outbound returns the established connections that the container opened:
// inbound ones (local port is a listening port) are dropped, as are sockets to
// the unspecified address.
func Outbound(conns []Conn) []Conn {
	listen := map[int]bool{}
	for _, c := range conns {
		if c.State == "0A" {
			listen[c.LocalPort] = true
		}
	}
	var out []Conn
	for _, c := range conns {
		if c.State != "01" || listen[c.LocalPort] || c.Remote.IsUnspecified() {
			continue
		}
		out = append(out, c)
	}
	return out
}

// ErrRuntimeUnavailable means the container offers no way to list sockets (no
// cat, no docker exec, no host pid view). Callers degrade to a warning line.
var ErrRuntimeUnavailable = errors.New("connection observation unavailable for this container")

// RunFunc runs a command and returns its stdout (docker exec / docker inspect /
// reading a /proc file on the host). It is injected so the observer is testable.
type RunFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

// Observe lists the container's established outbound TCP connections and
// classifies the destinations. Nothing is installed in the user's image: it
// uses the image's own cat when present and otherwise the host's /proc view of
// the container's init process.
func Observe(ctx context.Context, run RunFunc, readHostFile func(string) ([]byte, error), container string, c *Classifier) ([]Finding, error) {
	if c == nil {
		c = &Classifier{}
	}
	var conns []Conn
	got := false
	for _, f := range []struct {
		file string
		v6   bool
	}{{"/proc/net/tcp", false}, {"/proc/net/tcp6", true}} {
		out, err := run(ctx, "docker", "exec", container, "cat", f.file)
		if err == nil {
			got = true
			conns = append(conns, ParseProcNet(strings.NewReader(string(out)), f.v6)...)
		}
	}
	if !got && readHostFile != nil { // image without shell: use the host's view of the container's netns
		pidOut, err := run(ctx, "docker", "inspect", "-f", "{{.State.Pid}}", container)
		pid := strings.TrimSpace(string(pidOut))
		if n, perr := strconv.Atoi(pid); err == nil && perr == nil && n > 0 {
			for _, f := range []struct {
				file string
				v6   bool
			}{{"tcp", false}, {"tcp6", true}} {
				if data, err := readHostFile(fmt.Sprintf("/proc/%d/net/%s", n, f.file)); err == nil {
					got = true
					conns = append(conns, ParseProcNet(strings.NewReader(string(data)), f.v6)...)
				}
			}
		}
	}
	if !got {
		return nil, ErrRuntimeUnavailable
	}
	var out []Finding
	seen := map[string]bool{}
	for _, cn := range Outbound(conns) {
		ep := Endpoint{Host: cn.Remote.String(), Port: cn.RemotePort}
		f, ok := newFinding(c, ep, "runtime")
		if ok && !seen[f.ID] {
			seen[f.ID] = true
			out = append(out, f)
		}
	}
	return out, nil
}
