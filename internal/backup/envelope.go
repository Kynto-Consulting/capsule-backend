// Package backup implements per-project data backups: streamed dumps, client-side
// envelope encryption, S3 storage, scheduling, retention, restore and verification.
package backup

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/kynto/capsule/backend/pkg/crypto"
)

// Envelope encryption: every backup gets a random 256-bit data key (DEK). The data is
// encrypted in a chunked AES-256-GCM stream (so multi-GB dumps never sit in memory) and the
// DEK, wrapped with a key derived from CAPSULE_SECRET_KEY, travels in the object metadata.
//
// Stream layout: header(16) = "CBKP" | version(1) | chunkSize(4, BE) | noncePrefix(7),
// then chunks of (plaintext<=chunkSize)+16-byte tag. Chunk nonce = prefix | counter(4, BE) |
// lastFlag(1); the header is the AAD, so reordering, dropping or truncating chunks is detected.

const (
	chunkSize  = 1 << 20
	headerLen  = 16
	tagLen     = 16
	envVersion = 1
)

var (
	ErrAuth      = errors.New("backup: data authentication failed (corrupted or tampered)")
	ErrTruncated = errors.New("backup: data truncated")
	magic        = []byte("CBKP")
)

// NewDEK returns a fresh random data key.
func NewDEK() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

// WrapDEK encrypts dek with the platform secret; the result is safe for S3 object metadata.
func WrapDEK(dek []byte, secret string) (string, error) {
	enc, err := crypto.Encrypt(dek, secret)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

// UnwrapDEK reverses WrapDEK.
func UnwrapDEK(wrapped, secret string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, fmt.Errorf("backup: bad wrapped key: %w", err)
	}
	dek, err := crypto.Decrypt(raw, secret)
	if err != nil {
		return nil, fmt.Errorf("backup: cannot unwrap data key (wrong CAPSULE_SECRET_KEY?): %w", err)
	}
	if len(dek) != 32 {
		return nil, errors.New("backup: bad data key length")
	}
	return dek, nil
}

func newGCM(dek []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func chunkNonce(prefix []byte, counter uint32, last bool) []byte {
	n := make([]byte, 12)
	copy(n, prefix)
	binary.BigEndian.PutUint32(n[7:], counter)
	if last {
		n[11] = 1
	}
	return n
}

// EncryptWriter encrypts everything written to it. Close MUST be called to emit the final chunk.
type EncryptWriter struct {
	w       io.Writer
	aead    cipher.AEAD
	header  []byte
	prefix  []byte
	buf     []byte
	counter uint32
	started bool
	closed  bool
}

func NewEncryptWriter(w io.Writer, dek []byte) (*EncryptWriter, error) {
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, 7)
	if _, err := io.ReadFull(rand.Reader, prefix); err != nil {
		return nil, err
	}
	h := make([]byte, headerLen)
	copy(h, magic)
	h[4] = envVersion
	binary.BigEndian.PutUint32(h[5:9], chunkSize)
	// bytes 9..15 hold the nonce prefix (7 bytes)
	copy(h[9:], prefix)
	return &EncryptWriter{w: w, aead: aead, header: h, prefix: prefix, buf: make([]byte, 0, chunkSize)}, nil
}

func (e *EncryptWriter) start() error {
	if e.started {
		return nil
	}
	e.started = true
	_, err := e.w.Write(e.header)
	return err
}

func (e *EncryptWriter) flush(last bool) error {
	if err := e.start(); err != nil {
		return err
	}
	ct := e.aead.Seal(nil, chunkNonce(e.prefix, e.counter, last), e.buf, e.header)
	e.counter++
	e.buf = e.buf[:0]
	_, err := e.w.Write(ct)
	return err
}

func (e *EncryptWriter) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errors.New("backup: write after close")
	}
	total := len(p)
	for len(p) > 0 {
		if len(e.buf) == chunkSize { // more data arrived, so the full chunk is not the last one
			if err := e.flush(false); err != nil {
				return 0, err
			}
		}
		n := chunkSize - len(e.buf)
		if n > len(p) {
			n = len(p)
		}
		e.buf = append(e.buf, p[:n]...)
		p = p[n:]
	}
	return total, nil
}

// Close writes the final (possibly empty) chunk.
func (e *EncryptWriter) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	return e.flush(true)
}

type decryptReader struct {
	br      *bufio.Reader
	aead    cipher.AEAD
	header  []byte
	prefix  []byte
	plain   []byte
	counter uint32
	done    bool
	err     error
	started bool
}

// NewDecryptReader returns a reader yielding the plaintext. Corruption, tampering and
// truncation surface as ErrAuth / ErrTruncated from Read (never as a clean io.EOF).
func NewDecryptReader(r io.Reader, dek []byte) io.Reader {
	aead, err := newGCM(dek)
	d := &decryptReader{br: bufio.NewReaderSize(r, chunkSize+tagLen+1), aead: aead}
	if err != nil {
		d.err = err
	}
	return d
}

func (d *decryptReader) readHeader() error {
	h := make([]byte, headerLen)
	if _, err := io.ReadFull(d.br, h); err != nil {
		return ErrTruncated
	}
	if string(h[:4]) != string(magic) || h[4] != envVersion || binary.BigEndian.Uint32(h[5:9]) != chunkSize {
		return errors.New("backup: not a Capsule backup stream")
	}
	d.header = h
	d.prefix = h[9:16]
	return nil
}

func (d *decryptReader) next() error {
	if !d.started {
		d.started = true
		if err := d.readHeader(); err != nil {
			return err
		}
	}
	ct := make([]byte, chunkSize+tagLen)
	n, err := io.ReadFull(d.br, ct)
	last := false
	switch {
	case err == nil:
		if _, perr := d.br.Peek(1); perr == io.EOF {
			last = true
		} else if perr != nil {
			return perr
		}
	case errors.Is(err, io.ErrUnexpectedEOF):
		last = true
	case errors.Is(err, io.EOF):
		return ErrTruncated
	default:
		return err
	}
	if n < tagLen {
		return ErrTruncated
	}
	pt, oerr := d.aead.Open(nil, chunkNonce(d.prefix, d.counter, last), ct[:n], d.header)
	if oerr != nil {
		return ErrAuth
	}
	d.counter++
	d.plain = pt
	d.done = last
	return nil
}

func (d *decryptReader) Read(p []byte) (int, error) {
	for len(d.plain) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			return 0, io.EOF
		}
		if err := d.next(); err != nil {
			d.err = err
			return 0, err
		}
	}
	n := copy(p, d.plain)
	d.plain = d.plain[n:]
	return n, nil
}
