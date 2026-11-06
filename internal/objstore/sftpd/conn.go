package sftpd

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// limitedConn applies an idle timeout (no bytes read for idle => the read fails and the connection closes) and
// bandwidth limits (per connection and global) to the raw TCP connection, so both uploads and downloads are capped.
type limitedConn struct {
	net.Conn
	idle   time.Duration
	active atomic.Bool // false during the handshake (a hard deadline covers it)
	conn   *rate.Limiter
	global *rate.Limiter
	ctx    context.Context
	rx, tx atomic.Int64
}

func newLimiter(bps int64) *rate.Limiter {
	if bps <= 0 {
		return nil
	}
	burst := int(bps)
	if burst < 256<<10 {
		burst = 256 << 10
	}
	return rate.NewLimiter(rate.Limit(bps), burst)
}

func wait(ctx context.Context, l *rate.Limiter, n int) {
	for n > 0 && l != nil {
		step := n
		if step > l.Burst() {
			step = l.Burst()
		}
		if l.WaitN(ctx, step) != nil {
			return
		}
		n -= step
	}
}

func (c *limitedConn) Read(p []byte) (int, error) {
	if c.active.Load() && c.idle > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.rx.Add(int64(n))
		wait(c.ctx, c.conn, n)
		wait(c.ctx, c.global, n)
	}
	return n, err
}

func (c *limitedConn) Write(p []byte) (int, error) {
	wait(c.ctx, c.conn, len(p))
	wait(c.ctx, c.global, len(p))
	if c.active.Load() && c.idle > 0 {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(c.idle))
	}
	n, err := c.Conn.Write(p)
	c.tx.Add(int64(n))
	return n, err
}
