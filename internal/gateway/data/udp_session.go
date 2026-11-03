package data

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kynto/capsule/backend/internal/gateway/data/tunnel"
)

// maxUDPDatagram is the protocol maximum of one datagram (PROTOCOL.md 10.3).
const maxUDPDatagram = tunnel.MaxDatagram

// datagramBuf is the unit of the buffer pool: one datagram plus one byte to detect oversize reads.
type datagramBuf [maxUDPDatagram + 1]byte

var dgPool = sync.Pool{New: func() any { return new(datagramBuf) }}

// datagramConn is the client side of a UDP session: a sequence of datagrams plus keepalives. The stream transport
// (transport 2, len16 frames over the TLS connection) implements it; the QUIC transport (transport 3, udp_quic.go)
// will implement the same interface so the session logic below is shared.
type datagramConn interface {
	// ReadDatagram reads the next datagram into buf. (0, nil) is a keepalive. tunnel.ErrFrameTooLarge is a protocol
	// error that must end the session; io.EOF is an orderly end.
	ReadDatagram(buf []byte) (int, error)
	WriteDatagram(p []byte) error
	WriteKeepalive() error
	// Interrupt makes a blocked ReadDatagram return (used to stop the reader).
	Interrupt()
	// Close ends the session in an orderly way (close_notify / FIN) without destroying data already written.
	Close()
}

// ---------------- stream transport (transport 2) ----------------

// streamWriteTimeout bounds one write to a client that stopped reading.
const streamWriteTimeout = 10 * time.Second

type streamDatagrams struct {
	c  net.Conn
	r  io.Reader
	wb *datagramBuf
}

func newStreamDatagrams(c net.Conn, pre []byte) *streamDatagrams {
	var r io.Reader = c
	if len(pre) > 0 {
		r = io.MultiReader(&bytesReader{b: pre}, c)
	}
	return &streamDatagrams{c: c, r: r, wb: dgPool.Get().(*datagramBuf)}
}

type bytesReader struct{ b []byte }

func (r *bytesReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// readUDPFrame reads one len16 frame. It never allocates and never reads more than the frame announces.
// (0, nil) is a keepalive; a frame longer than the protocol maximum yields tunnel.ErrFrameTooLarge; an end of
// stream between frames yields io.EOF and inside a frame io.ErrUnexpectedEOF.
func readUDPFrame(r io.Reader, buf []byte) (int, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n > maxUDPDatagram {
		return 0, tunnel.ErrFrameTooLarge
	}
	if n == 0 {
		return 0, nil
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, err
	}
	return n, nil
}

func (s *streamDatagrams) ReadDatagram(buf []byte) (int, error) { return readUDPFrame(s.r, buf) }

func (s *streamDatagrams) WriteDatagram(p []byte) error {
	b := s.wb[:0]
	b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
	b = append(b, p...)
	s.c.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
	_, err := s.c.Write(b)
	return err
}

func (s *streamDatagrams) WriteKeepalive() error {
	s.c.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
	_, err := s.c.Write([]byte{0, 0})
	return err
}

func (s *streamDatagrams) Interrupt() { s.c.SetReadDeadline(time.Unix(1, 0)) }

// Close sends our FIN/close_notify and reads what the client still sends for a moment: closing a TCP socket with
// unread data makes the kernel answer RST, which could destroy the last datagrams before the client reads them.
func (s *streamDatagrams) Close() {
	if cw, ok := s.c.(closeWriter); ok {
		s.c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		cw.CloseWrite()
	}
	s.c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	io.Copy(io.Discard, io.LimitReader(s.c, lingerReadLimit))
	s.c.Close()
	if s.wb != nil {
		dgPool.Put(s.wb)
		s.wb = nil
	}
}

// ---------------- session ----------------

type udpParams struct {
	Idle        time.Duration // no client frame and no destination datagram for this long ends the session
	Keepalive   time.Duration // keepalive towards the client after this long without sending anything
	MaxDatagram int           // larger datagrams are dropped (never close the session)
	QueueBytes  int           // destination-to-client queue budget
}

// CloseProtocol is the close reason of a session ended by a protocol violation.
const CloseProtocol = "protocol_error"

type udpResult struct {
	BytesIn, BytesOut   int64 // client to destination, destination to client
	DgIn, DgOut         int64
	Keepalives          int64
	DropQueue, DropSize int64
	DropDest            int64 // writes to the destination that failed (e.g. ICMP port unreachable)
	Reason              string
}

type udpObserver interface {
	datagram(dir string, n int)
	dropped(reason string)
}

type nopObserver struct{}

func (nopObserver) datagram(string, int) {}
func (nopObserver) dropped(string)       {}

type queued struct {
	b *datagramBuf
	n int
}

// runUDPSession relays datagrams between the client and the connected destination socket until the client ends,
// the session is idle, or ctx is done. It closes dc and uc.
func runUDPSession(ctx context.Context, dc datagramConn, uc net.Conn, p udpParams, obs udpObserver) udpResult {
	if obs == nil {
		obs = nopObserver{}
	}
	if p.MaxDatagram <= 0 || p.MaxDatagram > maxUDPDatagram {
		p.MaxDatagram = maxUDPDatagram
	}
	if p.QueueBytes <= 0 {
		p.QueueBytes = 256 << 10
	}
	if p.Keepalive <= 0 {
		p.Keepalive = p.Idle / 3
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		bytesIn, bytesOut           atomic.Int64
		dgIn, dgOut, ka             atomic.Int64
		dropQueue, dropSize, dropDe atomic.Int64
		last                        atomic.Int64
		reason                      atomic.Value
		queuedBytes                 atomic.Int64
	)
	last.Store(time.Now().UnixNano())
	stop := func(r string) {
		reason.CompareAndSwap(nil, r)
		cancel()
	}
	q := make(chan queued, 256)
	var wg sync.WaitGroup
	wg.Add(2)

	// client -> destination
	go func() {
		defer wg.Done()
		buf := dgPool.Get().(*datagramBuf)
		defer dgPool.Put(buf)
		for {
			n, err := dc.ReadDatagram(buf[:])
			if err != nil {
				switch {
				case errors.Is(err, io.EOF):
					stop(CloseNormal)
				case errors.Is(err, tunnel.ErrFrameTooLarge):
					stop(CloseProtocol)
				case isTimeout(err) && ctx.Err() != nil:
					stop(CloseNormal) // interrupted by the session ending
				default:
					stop(ClosePeerReset)
				}
				return
			}
			last.Store(time.Now().UnixNano())
			if n == 0 {
				ka.Add(1)
				continue
			}
			if n > p.MaxDatagram {
				dropSize.Add(1)
				obs.dropped("oversize_in")
				continue
			}
			if _, werr := uc.Write(buf[:n]); werr != nil {
				if errors.Is(werr, net.ErrClosed) {
					return
				}
				dropDe.Add(1)
				obs.dropped("dest_write")
				continue
			}
			dgIn.Add(1)
			bytesIn.Add(int64(n))
			obs.datagram("in", n)
		}
	}()

	// destination -> queue
	go func() {
		defer wg.Done()
		buf := dgPool.Get().(*datagramBuf)
		defer dgPool.Put(buf)
		errs := 0
		for {
			n, err := uc.Read(buf[:p.MaxDatagram+1])
			if err != nil {
				if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
					return
				}
				// ICMP errors of a connected UDP socket surface as read errors: the session lives on
				if errs++; errs > 50 {
					stop(CloseError)
					return
				}
				time.Sleep(2 * time.Millisecond)
				continue
			}
			errs = 0
			last.Store(time.Now().UnixNano())
			if n == 0 {
				continue
			}
			if n > p.MaxDatagram {
				dropSize.Add(1)
				obs.dropped("oversize_out")
				continue
			}
			if queuedBytes.Add(int64(n)) > int64(p.QueueBytes) {
				queuedBytes.Add(-int64(n))
				dropQueue.Add(1)
				obs.dropped("queue_full")
				continue
			}
			cp := dgPool.Get().(*datagramBuf)
			copy(cp[:], buf[:n])
			select {
			case q <- queued{cp, n}:
			default:
				queuedBytes.Add(-int64(n))
				dgPool.Put(cp)
				dropQueue.Add(1)
				obs.dropped("queue_full")
			}
		}
	}()

	// queue -> client, keepalives and the inactivity clock (this goroutine)
	tick := p.Idle / 4
	if p.Keepalive > 0 && (tick <= 0 || p.Keepalive < tick) {
		tick = p.Keepalive
	}
	if tick < 5*time.Millisecond {
		tick = 5 * time.Millisecond
	}
	tk := time.NewTicker(tick)
	lastSent := time.Now()
	write := func(it queued) bool {
		queuedBytes.Add(-int64(it.n))
		err := dc.WriteDatagram(it.b[:it.n])
		dgPool.Put(it.b)
		if err != nil {
			if isTimeout(err) {
				stop(CloseIdle) // the client stopped reading
			} else {
				stop(ClosePeerReset)
			}
			return false
		}
		lastSent = time.Now()
		dgOut.Add(1)
		bytesOut.Add(int64(it.n))
		obs.datagram("out", it.n)
		return true
	}
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case it := <-q:
			if !write(it) {
				break loop
			}
		case now := <-tk.C:
			if p.Idle > 0 && now.Sub(time.Unix(0, last.Load())) > p.Idle {
				stop(CloseIdle)
				break loop
			}
			if p.Keepalive > 0 && now.Sub(lastSent) >= p.Keepalive {
				if err := dc.WriteKeepalive(); err != nil {
					stop(ClosePeerReset)
					break loop
				}
				lastSent = now
			}
		}
	}
	tk.Stop()
	stop(CloseNormal)
	uc.Close()
	dc.Interrupt()
	wg.Wait()
	// flush what the destination already answered, then end the stream in an orderly way
	flushing := true
	if r, _ := reason.Load().(string); r == ClosePeerReset {
		flushing = false
	}
drain:
	for {
		select {
		case it := <-q:
			if flushing {
				if !write(it) { // write returns the buffer to the pool
					flushing = false
				}
			} else {
				queuedBytes.Add(-int64(it.n))
				dgPool.Put(it.b)
			}
		default:
			break drain
		}
	}
	dc.Close()
	res := udpResult{
		BytesIn: bytesIn.Load(), BytesOut: bytesOut.Load(), DgIn: dgIn.Load(), DgOut: dgOut.Load(), Keepalives: ka.Load(),
		DropQueue: dropQueue.Load(), DropSize: dropSize.Load(), DropDest: dropDe.Load(),
	}
	res.Reason, _ = reason.Load().(string)
	if res.Reason == "" {
		res.Reason = CloseNormal
	}
	return res
}
