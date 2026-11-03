//go:build !linux

package data

import (
	"context"
	"net"
	"time"
)

// listenTCP opens a TCP listener (no SO_REUSEPORT outside Linux: the gateway targets Linux in production).
func listenTCP(ctx context.Context, addr string, reuse bool) (net.Listener, error) {
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	return lc.Listen(ctx, "tcp", addr)
}

// ReusePortSupported reports whether SO_REUSEPORT is available on this platform.
const ReusePortSupported = false
