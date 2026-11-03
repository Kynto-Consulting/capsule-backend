//go:build linux

package data

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kynto/capsule/backend/internal/gateway/data/tunnel"
)

// These tests run the real capsule-gateway binary as a separate process, so descriptors and memory are those of the
// gateway alone. They need CAPSULE_GW_BIN (path to a linux build of ./cmd/capsule-gateway) and are skipped otherwise:
//   GOOS=linux go build -o /tmp/capsule-gateway ./cmd/capsule-gateway
//   CAPSULE_GW_BIN=/tmp/capsule-gateway go test -run Process -v ./internal/gateway/data/

func gwBin(t *testing.T) string {
	b := os.Getenv("CAPSULE_GW_BIN")
	if b == "" {
		t.Skip("CAPSULE_GW_BIN not set")
	}
	return b
}

func freePort(t testing.TB) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type gwProc struct {
	cmd     *exec.Cmd
	port    int
	admin   string
	out     *syncBuf
	exited  chan struct{}
	exitErr error
}

func startGWProc(t *testing.T, bin string, cp *fakeControl, port int, extraEnv ...string) *gwProc {
	t.Helper()
	dir := t.TempDir()
	cert := selfSigned(t, "gateway", "tcp."+testZone, "udp."+testZone, "*.apps.test", "*.git.test", "*.db.test")
	c, k := writePair(t, dir, "gw", cert)
	ctlURL := httpTestServer(t, cp)
	if port == 0 {
		port = freePort(t)
	}
	admin := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("CAPSULE_GW_LISTEN=127.0.0.1:%d", port),
		"CAPSULE_GW_CONTROL_URL="+ctlURL,
		"CAPSULE_GW_SECRET="+cp.secret,
		"CAPSULE_GW_ZONE="+testZone,
		"CAPSULE_GW_TLS_CERT="+c, "CAPSULE_GW_TLS_KEY="+k,
		"CAPSULE_GW_METRICS_ADDR="+admin,
		"CAPSULE_GW_ALLOW_LOOPBACK_DEST=true",
		"CAPSULE_GW_NEW_CONNS_PER_IP=1000000", "CAPSULE_GW_PREAUTH_PER_IP=1000000",
		"CAPSULE_GW_ROUTE_MAX_CONNS=1000000", "CAPSULE_GW_ROUTE_MAX_CONNS_PER_IP=1000000", "CAPSULE_GW_ROUTE_CONN_RATE=1000000",
		"CAPSULE_GW_MAX_CONNS=100000", "CAPSULE_GW_ROUTES_WAIT=2s", "CAPSULE_GW_DRAIN_GRACE=1s", "CAPSULE_GW_DENY_DELAY=50ms",
		"CAPSULE_GW_REUSEPORT=true", "CAPSULE_GW_LOG_LEVEL=warn")
	cmd.Env = append(cmd.Env, extraEnv...)
	out := &syncBuf{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &gwProc{cmd: cmd, port: port, admin: admin, out: out, exited: make(chan struct{})}
	go func() { p.exitErr = cmd.Wait(); close(p.exited) }()
	t.Cleanup(func() {
		select {
		case <-p.exited:
		default:
			cmd.Process.Kill()
			<-p.exited
		}
	})
	waitFor(t, 10*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", admin, 200*time.Millisecond)
		if err != nil {
			return false
		}
		c.Close()
		return p.ready()
	})
	return p
}

func (p *gwProc) ready() bool {
	c := net.Dialer{Timeout: time.Second}
	conn, err := c.Dial("tcp", p.admin)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	io.WriteString(conn, "GET /readyz HTTP/1.0\r\n\r\n")
	line, _ := bufio.NewReader(conn).ReadString('\n')
	return strings.Contains(line, "200")
}

func (p *gwProc) addr() string { return fmt.Sprintf("127.0.0.1:%d", p.port) }

func (p *gwProc) fds(t testing.TB) int {
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", p.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// pipes counts descriptors that are pipes (the splice(2) buffers of io.Copy between two TCP sockets).
func (p *gwProc) pipes(t testing.TB) int {
	n := 0
	ents, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", p.cmd.Process.Pid))
	for _, e := range ents {
		if l, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", p.cmd.Process.Pid, e.Name())); err == nil && strings.HasPrefix(l, "pipe:") {
			n++
		}
	}
	return n
}

func (p *gwProc) rssKB(t testing.TB) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", p.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmRSS:") {
			f := strings.Fields(l)
			n, _ := strconv.Atoi(f[1])
			return n
		}
	}
	return 0
}

func loadN() int {
	if v := os.Getenv("CAPSULE_GW_LOAD_N"); v != "" {
		n, _ := strconv.Atoi(v)
		return n
	}
	return 2000
}

func record(t *testing.T, format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	t.Log(line)
	if f := os.Getenv("CAPSULE_GW_RESULTS"); f != "" {
		fh, err := os.OpenFile(f, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintln(fh, line)
			fh.Close()
		}
	}
}

// openIdle opens n established, idle connections through the gateway (full TLS handshake and first bytes seen).
func openIdle(t *testing.T, addr, sni string, n int, banner bool) []net.Conn {
	conns := make([]net.Conn, n)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, 64)
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := net.DialTimeout("tcp", addr, 10*time.Second)
			if err == nil {
				tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
				c.SetDeadline(time.Now().Add(30 * time.Second))
				if err = tc.Handshake(); err == nil {
					if banner {
						var b [1]byte
						_, err = io.ReadFull(tc, b[:])
					}
					c.SetDeadline(time.Time{})
					conns[i] = tc
				} else {
					c.Close()
				}
			}
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("opening %d connections: %v", n, firstErr)
	}
	return conns
}

func TestProcessLoadIdleConnections(t *testing.T) {
	bin := gwBin(t)
	n := loadN()
	cp := newFakeControl()
	pass := tlsBackend(t, "PASS")
	echo := echoBackend(t)
	cp.SetRoutes(1, rt("r-pass", "pass.apps.test", "tls", "passthrough", pass), rt("r-term", "term.git.test", "ssh", "terminate", echo))
	p := startGWProc(t, bin, cp, 0)
	baseRSS, baseFD := p.rssKB(t), p.fds(t)
	record(t, "gateway process base: rss=%d kB fds=%d", baseRSS, baseFD)

	for _, mode := range []struct {
		name, sni string
		banner    bool
	}{{"passthrough", "pass.apps.test", true}, {"terminate", "term.git.test", false}} {
		conns := openIdle(t, p.addr(), mode.sni, n, mode.banner)
		time.Sleep(500 * time.Millisecond)
		rss, fd, pipes := p.rssKB(t), p.fds(t), p.pipes(t)
		perConnFD := float64(fd-baseFD) / float64(n)
		perConnKB := float64(rss-baseRSS) / float64(n)
		record(t, "%s N=%d: rss=%d kB (+%.1f kB/conn) fds=%d (%.2f fds/conn) pipe fds=%d", mode.name, n, rss, perConnKB, fd, perConnFD, pipes)
		if perConnFD > 2.1 {
			t.Errorf("%s: %.2f descriptors per connection, want 2 (client socket + destination socket)", mode.name, perConnFD)
		}
		if pipes > 4 {
			t.Errorf("%s: %d pipe descriptors: splice buffers must not be held", mode.name, pipes)
		}
		if perConnKB > 80 {
			t.Errorf("%s: %.1f kB per idle connection is far above the measured prototype (25-75 kB)", mode.name, perConnKB)
		}
		for _, c := range conns {
			c.Close()
		}
		waitFor(t, 30*time.Second, func() bool { return p.fds(t) <= baseFD+8 })
		record(t, "%s after close: rss=%d kB fds=%d", mode.name, p.rssKB(t), p.fds(t))
	}
}

// ---- zero-downtime update with two processes (SO_REUSEPORT) and drain ----

func TestProcessUpdateWithoutCuttingConnections(t *testing.T) {
	bin := gwBin(t)
	cp := newFakeControl()
	echo := echoBackend(t)
	cp.SetRoutes(1, tunnelRoute("t-db", "mi-proyecto", "db", echo))
	port := freePort(t)
	old := startGWProc(t, bin, cp, port)

	long, resp := dialTunnel(t, old.addr(), capReq("mi-proyecto", "db"), nil)
	if resp.Status != 0 {
		t.Fatal(resp.Status)
	}
	echoOnce := func(c *tls.Conn, msg string) {
		t.Helper()
		io.WriteString(c, msg)
		buf := make([]byte, len(msg))
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
			t.Fatalf("echo %q: %q %v", msg, buf, err)
		}
	}
	echoOnce(long, "before-update")

	nw := startGWProc(t, bin, cp, port) // same port: SO_REUSEPORT
	// keep opening short connections while the old process drains: retry on 6/0x0601 like the client library does
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var mu sync.Mutex
	attempts, busy, hard := 0, 0, 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for try := 0; try < 5; try++ {
				c, err := net.DialTimeout("tcp", old.addr(), 2*time.Second)
				if err != nil {
					mu.Lock()
					attempts++
					hard++
					mu.Unlock()
					time.Sleep(20 * time.Millisecond)
					continue
				}
				tc := tls.Client(c, &tls.Config{ServerName: "tcp." + testZone, InsecureSkipVerify: true, NextProtos: []string{"capsule/1"}})
				hdr, _ := tunnel.EncodeRequest(capReq("mi-proyecto", "db"))
				tc.SetDeadline(time.Now().Add(5 * time.Second))
				var r *tunnel.Response
				if tc.Handshake() == nil {
					tc.Write(hdr)
					r = tryCAPR(tc)
				}
				tc.Close()
				mu.Lock()
				attempts++
				mu.Unlock()
				if r != nil && r.Status == 0 {
					break
				}
				mu.Lock()
				if r != nil && r.Code == 0x0601 {
					busy++
				} else {
					hard++
				}
				mu.Unlock()
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	time.Sleep(500 * time.Millisecond)
	old.cmd.Process.Signal(syscall.SIGTERM) // drain the old process
	time.Sleep(3 * time.Second)             // grace (1 s) + listeners closed
	echoOnce(long, "during-drain")
	close(stop)
	wg.Wait()
	select {
	case <-old.exited:
		t.Fatal("the old process exited while a connection was still open")
	default:
	}
	// new connections are served by the new process only
	c2, resp2 := dialTunnel(t, nw.addr(), capReq("mi-proyecto", "db"), nil)
	if resp2.Status != 0 {
		t.Fatal(resp2.Status)
	}
	c2.Close()
	long.Close()
	select {
	case <-old.exited:
		if old.exitErr != nil {
			t.Fatalf("old process exit: %v\n%s", old.exitErr, old.out.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the old process did not exit after its last connection ended")
	}
	record(t, "update with SO_REUSEPORT: %d connection attempts during the swap, %d answered 6/0x0601 (client retries), %d hard failures; the long connection survived", attempts, busy, hard)
	if hard > 0 {
		t.Logf("hard failures during the swap: %d (listener closed with a connection in its accept queue)", hard)
	}
	nw.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-nw.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("new process did not stop on SIGTERM")
	}
}

func tryCAPR(tc *tls.Conn) *tunnel.Response {
	var buf []byte
	tmp := make([]byte, 1)
	for {
		r, _, err := tunnel.DecodeResponse(buf, false)
		if err == nil {
			return r
		}
		if err != tunnel.ErrIncompleteResponse {
			return nil
		}
		m, rerr := tc.Read(tmp)
		buf = append(buf, tmp[:m]...)
		if rerr != nil && m == 0 {
			return nil
		}
	}
}

func TestProcessReloadsCertificateOnSIGHUPAndHealthcheck(t *testing.T) {
	bin := gwBin(t)
	cp := newFakeControl()
	cp.SetRoutes(1, rt("t", "x.git.test", "ssh", "terminate", echoBackend(t)))
	p := startGWProc(t, bin, cp, 0)
	c, err := tlsDial(t, p.addr(), "x.git.test")
	if err != nil {
		t.Fatal(err)
	}
	first := c.ConnectionState().PeerCertificates[0].SerialNumber.String()
	c.Close()
	// healthcheck mode of the binary (used by the Dockerfile HEALTHCHECK)
	hc := exec.Command(bin, "-healthcheck")
	hc.Env = append(os.Environ(), "CAPSULE_GW_METRICS_ADDR="+p.admin)
	if out, err := hc.CombinedOutput(); err != nil {
		t.Fatalf("healthcheck: %v %s", err, out)
	}
	// replace the certificate files and send SIGHUP
	var certPath, keyPath string
	for _, e := range p.cmd.Env {
		if v, ok := strings.CutPrefix(e, "CAPSULE_GW_TLS_CERT="); ok {
			certPath = v
		}
		if v, ok := strings.CutPrefix(e, "CAPSULE_GW_TLS_KEY="); ok {
			keyPath = v
		}
	}
	writePairAt(t, certPath, keyPath, selfSigned(t, "gateway", "tcp."+testZone, "x.git.test"))
	p.cmd.Process.Signal(syscall.SIGHUP)
	waitFor(t, 5*time.Second, func() bool {
		c, err := tlsDial(t, p.addr(), "x.git.test")
		if err != nil {
			return false
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].SerialNumber.String() != first
	})
	_ = filepath.Join
}

func TestProcessFailsWithoutSecret(t *testing.T) {
	bin := gwBin(t)
	cmd := exec.Command(bin)
	cmd.Env = []string{"CAPSULE_GW_CONTROL_URL=http://127.0.0.1:1"}
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "secret") {
		t.Fatalf("must refuse to start without the gateway secret: %v %s", err, out)
	}
}
