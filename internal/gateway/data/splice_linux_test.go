//go:build linux

package data

import (
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func selfPipeFDs() int {
	ents, _ := os.ReadDir("/proc/self/fd")
	n := 0
	for _, e := range ents {
		if l, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && strings.HasPrefix(l, "pipe:") {
			n++
		}
	}
	return n
}

// Root cause of the "6 descriptors per passthrough connection" anomaly of PLAN.md section 14: io.Copy between two
// *net.TCPConn uses splice(2) and holds a pipe pair (2 descriptors) per direction while idle. Relay does not.
func TestSpliceDescriptorControl(t *testing.T) {
	const n = 50
	measure := func(copyFn func(a, b net.Conn)) (pipes int) {
		base := selfPipeFDs()
		var cleanup []net.Conn
		for i := 0; i < n; i++ {
			cA, gwA := tcpPair(t)
			gwB, cB := tcpPair(t)
			go copyFn(gwA, gwB)
			cleanup = append(cleanup, cA, cB)
		}
		time.Sleep(300 * time.Millisecond)
		pipes = selfPipeFDs() - base
		for _, c := range cleanup {
			c.Close()
		}
		time.Sleep(200 * time.Millisecond)
		return pipes
	}
	withIOCopy := measure(func(a, b net.Conn) {
		done := make(chan struct{}, 2)
		go func() { io.Copy(b, a); done <- struct{}{} }()
		go func() { io.Copy(a, b); done <- struct{}{} }()
		<-done
		<-done
		a.Close()
		b.Close()
	})
	withRelay := measure(func(a, b net.Conn) { Relay(a, b, RelayOptions{Idle: 5 * time.Second}) })
	t.Logf("pipe descriptors for %d idle proxied connections: io.Copy=%d (%.1f per connection), Relay=%d", n, withIOCopy, float64(withIOCopy)/n, withRelay)
	if withIOCopy < 2*n {
		t.Skipf("this Go runtime does not hold splice pipes (%d); nothing to demonstrate", withIOCopy)
	}
	if withRelay > 4 {
		t.Fatalf("Relay holds %d pipe descriptors", withRelay)
	}
}
