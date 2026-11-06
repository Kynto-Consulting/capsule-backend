//go:build linux

package fnagent

import (
	"context"
	"net"
	"os"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/kynto/capsule/backend/internal/fn"
)

func init() {
	KernelFactory = func(ta fn.TunnelAssignment) (Tunnel, error) { return OpenKernel(ta, execRunner{}) }
}

// DialContext enters the namespace on a dedicated OS thread (never unlocked: the thread dies with the goroutine).
func (k *KernelTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread()
		f, err := os.Open("/var/run/netns/" + k.ns)
		if err != nil {
			ch <- res{nil, err}
			return
		}
		defer f.Close()
		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			ch <- res{nil, err}
			return
		}
		var d net.Dialer
		c, err := d.DialContext(ctx, network, addr)
		ch <- res{c, err}
	}()
	r := <-ch
	return r.c, r.err
}
