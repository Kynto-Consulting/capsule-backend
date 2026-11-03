//go:build linux

package data

import (
	"context"
	"net"
	"syscall"
	"time"
)

const soReusePort = 0xf // SO_REUSEPORT (same value on the architectures Capsule ships to)

// listenTCP opens a TCP listener. Wildcard IPv6 addresses ("[::]:443") are dual stack (IPV6_V6ONLY=0, the Go default
// for the "tcp" network on a wildcard address). With reuse, SO_REUSEPORT lets a new gateway process bind the same
// port while the old one drains (see Server.Drain).
func listenTCP(ctx context.Context, addr string, reuse bool) (net.Listener, error) {
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	if reuse {
		lc.Control = func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	return lc.Listen(ctx, "tcp", addr)
}

// ReusePortSupported reports whether SO_REUSEPORT is available on this platform.
const ReusePortSupported = true
