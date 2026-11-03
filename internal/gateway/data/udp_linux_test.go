//go:build linux

package data

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kynto/capsule/backend/internal/gateway/data/tunnel"
)

// Real UDP/TCP clients against a leased random port. Opt in with CAPSULE_GW_REAL=1 (needs nc, the OpenBSD netcat).
func TestRealNCAgainstPoolPort(t *testing.T) {
	realOnly(t)
	nc, err := exec.LookPath("nc")
	if err != nil {
		t.Skip("nc not installed")
	}
	ports := freePorts(t, "127.0.0.1", 2)
	echoU := startUDPEcho(t, "udp4", "127.0.0.1:0")
	echoT := echoBackend(t)
	ur := udpRoute("u1", "", "", echoU.Addr())
	tr := rt("t1", "", "tcp", "passthrough", echoT)
	g := startPoolGW(t, ports, "", func(c *Config) { c.Pool.FlowIdle = 5 * time.Second }, ur, tr)
	setSnap(g.cp, 2, []Route{ur, tr}, []Lease{lease(ports[0], ur), lease(ports[1], tr)})
	awaitPorts(t, g, []int{ports[1]}, []int{ports[0]})

	runNC := func(stdin string, args ...string) string {
		cmd := exec.Command(nc, args...)
		cmd.Stdin = strings.NewReader(stdin)
		out, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(out))
	}
	// UDP: nc -u sends one datagram per line and prints the reply
	got := runNC("hello-from-nc\n", "-u", "-w", "1", "127.0.0.1", strconv.Itoa(ports[0]))
	if got != "hello-from-nc" {
		t.Fatalf("nc -u through the pool: %q", got)
	}
	if echoU.recv.Load() != 1 {
		t.Fatalf("destination received %d datagrams", echoU.recv.Load())
	}
	// TCP: a plain TCP client through the leased port
	got = runNC("tcp-line\n", "-w", "1", "127.0.0.1", strconv.Itoa(ports[1]))
	if !strings.HasPrefix(got, "tcp-line") {
		t.Fatalf("nc through the tcp lease: %q", got)
	}
	t.Logf("nc -u echo OK (%q); nc tcp echo OK (%q)", "hello-from-nc", got)
}

func TestRealNCIPv6AgainstPoolPort(t *testing.T) {
	realOnly(t)
	nc, err := exec.LookPath("nc")
	if err != nil {
		t.Skip("nc not installed")
	}
	ports := freePorts(t, "::1", 1)
	echoU := startUDPEcho(t, "udp6", "[::1]:0")
	ur := udpRoute("u6", "", "", echoU.Addr())
	g := startPoolGW(t, ports, "::1", nil, ur)
	setSnap(g.cp, 2, []Route{ur}, []Lease{lease(ports[0], ur)})
	awaitPorts(t, g, nil, []int{ports[0]})
	cmd := exec.Command(nc, "-6", "-u", "-w", "1", "::1", strconv.Itoa(ports[0]))
	cmd.Stdin = strings.NewReader("v6-from-nc\n")
	out, _ := cmd.CombinedOutput()
	if strings.TrimSpace(string(out)) != "v6-from-nc" {
		t.Fatalf("nc -6 -u through the pool: %q", out)
	}
}

// ---- the real gateway binary: memory and descriptors per UDP session / flow ----
//
//	GOOS=linux go build -o /tmp/capsule-gateway ./cmd/capsule-gateway
//	CAPSULE_GW_BIN=/tmp/capsule-gateway CAPSULE_GW_LOAD_N=2000 go test -run ProcessUDP -v ./internal/gateway/data/

func openUDPSessions(t *testing.T, addr string, n int, project, service string) []*tls.Conn {
	conns := make([]*tls.Conn, n)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	var mu sync.Mutex
	var first error
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fail := func(err error) {
				mu.Lock()
				if first == nil {
					first = err
				}
				mu.Unlock()
			}
			c, err := net.DialTimeout("tcp", addr, 10*time.Second)
			if err != nil {
				fail(err)
				return
			}
			tc := tls.Client(c, &tls.Config{ServerName: "tcp." + testZone, InsecureSkipVerify: true, NextProtos: []string{"capsule/1"}, MinVersion: tls.VersionTLS13})
			c.SetDeadline(time.Now().Add(30 * time.Second))
			if err := tc.Handshake(); err != nil {
				fail(err)
				c.Close()
				return
			}
			hdr, _ := tunnel.EncodeRequest(udpReq(project, service))
			tc.Write(append(hdr, frame([]byte("hello"))...))
			r := tryCAPR(tc)
			if r == nil || r.Status != 0 {
				fail(fmt.Errorf("session %d: %+v", i, r))
				c.Close()
				return
			}
			buf := make([]byte, 64)
			if n, err := readUDPFrame(tc, buf); err != nil || string(buf[:n]) != "hello" {
				fail(fmt.Errorf("session %d echo: %v", i, err))
				c.Close()
				return
			}
			c.SetDeadline(time.Time{})
			conns[i] = tc
		}(i)
	}
	wg.Wait()
	if first != nil {
		t.Fatal(first)
	}
	return conns
}

func startUDPLoadGW(t *testing.T, n int) (*gwProc, *udpEchoSrv, int) {
	bin := gwBin(t)
	echo := startUDPEcho(t, "udp4", "127.0.0.1:0")
	ports := freePorts(t, "127.0.0.1", 1)
	ur := udpRoute("u1", "proj", "game", echo.Addr())
	cp := newFakeControl()
	setSnap(cp, 1, []Route{ur}, []Lease{lease(ports[0], ur)})
	big := "100000"
	p := startGWProc(t, bin, cp, 0,
		"CAPSULE_GW_UDP_SESSIONS_ROUTE="+big, "CAPSULE_GW_UDP_SESSIONS_IP="+big, "CAPSULE_GW_UDP_SESSIONS_PROJECT="+big,
		fmt.Sprintf("CAPSULE_GW_POOL=%d-%d", ports[0], ports[0]), "CAPSULE_GW_POOL_BIND=127.0.0.1",
		"CAPSULE_GW_POOL_FLOW_RATE=100000", "CAPSULE_GW_POOL_MAX_FLOWS="+strconv.Itoa(n+100), "CAPSULE_GW_POOL_FLOW_IDLE=10s")
	waitFor(t, 5*time.Second, func() bool {
		c, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[0])))
		if err != nil {
			return true // bound by the gateway
		}
		c.Close()
		return false
	})
	return p, echo, ports[0]
}

func TestProcessUDPTunnelLoad(t *testing.T) {
	n := loadN()
	p, _, _ := startUDPLoadGW(t, n)
	baseRSS, baseFD := p.rssKB(t), p.fds(t)
	record(t, "UDP gateway process base: rss=%d kB fds=%d", baseRSS, baseFD)
	conns := openUDPSessions(t, p.addr(), n, "proj", "game")
	time.Sleep(500 * time.Millisecond)
	rss, fd := p.rssKB(t), p.fds(t)
	perKB, perFD := float64(rss-baseRSS)/float64(n), float64(fd-baseFD)/float64(n)
	record(t, "UDP tunnel sessions N=%d: rss=%d kB (+%.1f kB/session, TLS connection included) fds=%d (%.2f fds/session)", n, rss, perKB, fd, perFD)
	if perFD > 2.1 {
		t.Errorf("%.2f descriptors per UDP session, want 2 (client socket + destination socket)", perFD)
	}
	if perKB > 90 {
		t.Errorf("%.1f kB per UDP session is above the budget", perKB)
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)
	for _, c := range conns {
		wg.Add(1)
		sem <- struct{}{}
		go func(c *tls.Conn) {
			defer wg.Done()
			defer func() { <-sem }()
			buf := make([]byte, 2048)
			for i := 0; i < 5; i++ {
				c.Write(frame(bytes.Repeat([]byte{'p'}, 512)))
				c.SetReadDeadline(time.Now().Add(10 * time.Second))
				if _, err := readUDPFrame(c, buf); err != nil {
					t.Errorf("echo under load: %v", err)
					return
				}
			}
		}(c)
	}
	wg.Wait()
	rssBusy := p.rssKB(t)
	record(t, "UDP tunnel sessions after 5 datagrams each: rss=%d kB (+%.1f kB/session over base)", rssBusy, float64(rssBusy-baseRSS)/float64(n))
	for _, c := range conns {
		c.Close()
	}
	waitFor(t, 30*time.Second, func() bool { return p.fds(t) <= baseFD+8 })
	record(t, "UDP tunnel after close: rss=%d kB (Go keeps freed heap) fds=%d", p.rssKB(t), p.fds(t))
}

func TestProcessUDPPoolLoad(t *testing.T) {
	n := loadN()
	p, _, port := startUDPLoadGW(t, n)
	baseRSS, baseFD := p.rssKB(t), p.fds(t)
	record(t, "UDP gateway process base: rss=%d kB fds=%d", baseRSS, baseFD)
	cs := make([]*net.UDPConn, n)
	addr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	for i := range cs {
		c, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			t.Fatal(err)
		}
		cs[i] = c
		c.Write([]byte("hi"))
		if i%100 == 99 { // keep the echo socket's receive queue from overflowing
			time.Sleep(20 * time.Millisecond)
		}
	}
	lost := 0 // a real UDP client retransmits its first datagram when nothing came back
	for _, c := range cs {
		buf := make([]byte, 16)
		c.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := c.Read(buf); err != nil {
			c.Write([]byte("hi"))
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Read(buf); err != nil {
				lost++
			}
		}
	}
	time.Sleep(300 * time.Millisecond)
	rss, fd := p.rssKB(t), p.fds(t)
	perKB, perFD := float64(rss-baseRSS)/float64(n), float64(fd-baseFD)/float64(n)
	record(t, "UDP pool flows N=%d (first echo lost by %d): rss=%d kB (+%.1f kB/flow) fds=%d (%.2f fds/flow; client sockets are in the test process)", n, lost, rss, perKB, fd, perFD)
	if perFD > 1.1 {
		t.Errorf("%.2f descriptors per flow, want 1", perFD)
	}
	if perKB > 40 {
		t.Errorf("%.1f kB per flow is above the budget", perKB)
	}
	if lost > 0 {
		t.Errorf("%d of %d flows never got an answer, even after one retransmission", lost, n)
	}
	for _, c := range cs {
		c.Close()
	}
	waitFor(t, 40*time.Second, func() bool { return p.fds(t) <= baseFD+4 })
	record(t, "UDP pool after idle timeout: rss=%d kB fds=%d", p.rssKB(t), p.fds(t))
}
