package data

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Why the relay uses its own copy loop instead of io.Copy:
// when both ends are *net.TCPConn, io.Copy uses splice(2) and Go keeps a pipe pair (2 descriptors) per direction
// while the copy runs, i.e. 2 sockets + 2 pipes x 2 directions = 6 descriptors per proxied connection
// (the anomaly noted in PLAN.md section 14: 3008 descriptors for 500 passthrough connections). A user-space loop with
// a small buffer that grows only while data is flowing costs 2 descriptors per connection and 8 KiB when idle.

const (
	smallBuf = 4 << 10
	bigBuf   = 32 << 10
)

var (
	smallPool = sync.Pool{New: func() any { b := make([]byte, smallBuf); return &b }}
	bigPool   = sync.Pool{New: func() any { b := make([]byte, bigBuf); return &b }}
)

type closeWriter interface{ CloseWrite() error }

// RelayOptions tunes a relay.
type RelayOptions struct {
	Idle     time.Duration // inactivity limit in either direction (0 = none)
	HalfIdle time.Duration // inactivity limit once one direction ended (0 = same as Idle)
}

// RelayResult reports a finished relay.
type RelayResult struct {
	AToB, BToA int64
	Reason     string // normal | idle | peer_reset | error
}

// Close reasons for the audit log (PROTOCOL.md section 13).
const (
	CloseNormal    = "normal"
	CloseIdle      = "idle"
	ClosePeerReset = "peer_reset"
	CloseDrain     = "drain"
	CloseError     = "error"
)

type relayState struct {
	idle     atomic.Int64 // nanoseconds, 0 = none
	last     atomic.Int64 // unix nanos of the last byte moved in any direction
	reason   atomic.Value // string
	aborted  atomic.Bool
	finished atomic.Int32
}

func (s *relayState) setReason(r string) {
	s.reason.CompareAndSwap(nil, r)
}

// Relay copies a<->b with independent half-close (PROTOCOL.md 9.1): EOF from one side becomes CloseWrite (FIN or TLS
// close_notify) on the other and the opposite direction keeps flowing; an error or reset aborts both. Both
// connections are closed on return.
func Relay(a, b net.Conn, o RelayOptions) RelayResult {
	st := &relayState{}
	st.idle.Store(int64(o.Idle))
	st.last.Store(time.Now().UnixNano())
	var ab, ba int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); ab = copyDir(b, a, st, o) }()
	go func() { defer wg.Done(); ba = copyDir(a, b, st, o) }()
	wg.Wait()
	a.Close()
	b.Close()
	reason := CloseNormal
	if r, _ := st.reason.Load().(string); r != "" {
		reason = r
	}
	return RelayResult{AToB: ab, BToA: ba, Reason: reason}
}

func copyDir(dst, src net.Conn, st *relayState, o RelayOptions) (total int64) {
	buf := smallPool.Get().(*[]byte)
	var big *[]byte
	cur := *buf
	defer func() {
		smallPool.Put(buf)
		if big != nil {
			bigPool.Put(big)
		}
	}()
	abort := func(reason string) {
		st.setReason(reason)
		if st.aborted.CompareAndSwap(false, true) {
			dst.Close()
			src.Close()
		}
	}
	for {
		idle := time.Duration(st.idle.Load())
		if idle > 0 {
			src.SetReadDeadline(time.Now().Add(idle))
		} else {
			src.SetReadDeadline(time.Time{})
		}
		n, rerr := src.Read(cur)
		if n > 0 {
			now := time.Now()
			st.last.Store(now.UnixNano())
			wt := idle
			if wt <= 0 {
				wt = 10 * time.Minute
			}
			dst.SetWriteDeadline(now.Add(wt))
			if _, werr := dst.Write(cur[:n]); werr != nil {
				if isTimeout(werr) {
					abort(CloseIdle)
				} else {
					abort(ClosePeerReset)
				}
				return total
			}
			total += int64(n)
			// grow while the stream fills the buffer, shrink as soon as it stops
			if n == len(cur) && big == nil {
				big = bigPool.Get().(*[]byte)
				cur = *big
			} else if big != nil && n < len(cur) {
				bigPool.Put(big)
				big, cur = nil, *buf
			}
		}
		if rerr != nil {
			switch {
			case errors.Is(rerr, io.EOF):
				if cw, ok := dst.(closeWriter); ok {
					cw.CloseWrite()
				}
				// first direction done: the remaining one gets the (shorter) half-close idle limit
				if st.finished.Add(1) == 1 {
					hi := o.HalfIdle
					if hi <= 0 {
						hi = o.Idle
					}
					if hi > 0 && (time.Duration(st.idle.Load()) == 0 || hi < time.Duration(st.idle.Load())) {
						st.idle.Store(int64(hi))
					}
					// the other direction reads from dst and is probably blocked with the old, longer deadline:
					// re-arm it so the half-close limit applies from now
					if eff := time.Duration(st.idle.Load()); eff > 0 {
						dst.SetReadDeadline(time.Now().Add(eff))
					}
				}
				return total
			case isTimeout(rerr):
				// the other direction may have been active meanwhile
				if idle > 0 && time.Since(time.Unix(0, st.last.Load())) < time.Duration(st.idle.Load()) {
					continue
				}
				abort(CloseIdle)
				return total
			default:
				abort(ClosePeerReset)
				return total
			}
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}
