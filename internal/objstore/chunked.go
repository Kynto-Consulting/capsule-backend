package objstore

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"hash"
	"io"
	"strconv"
	"strings"
)

// chunkReader decodes an aws-chunked body (STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER] and
// STREAMING-UNSIGNED-PAYLOAD-TRAILER). Chunk signatures are verified when key is set; the trailer
// (checksums) is consumed and ignored: object integrity is covered by the MD5 ETag and, for signed
// uploads, by every chunk signature.
type chunkReader struct {
	br      *bufio.Reader
	key     []byte // nil: unsigned
	stamp   string // 20060102T150405Z
	scope   string // date/region/service/aws4_request
	prevSig string

	remain int64
	h      hash.Hash
	sig    string
	done   bool
	err    error
}

func newChunkReader(r io.Reader, a *parsedAuth, secret string) *chunkReader {
	c := &chunkReader{br: bufio.NewReaderSize(r, 64<<10)}
	if strings.HasPrefix(a.PayloadHash, "STREAMING-AWS4-HMAC-SHA256") {
		c.key = signingKey(secret, a.Date, a.Region, a.Service)
		c.stamp = a.Time.UTC().Format("20060102T150405Z")
		c.scope = a.Date + "/" + a.Region + "/" + a.Service + "/aws4_request"
		c.prevSig = a.Signature
	}
	return c
}

func (c *chunkReader) header() error {
	line, err := c.br.ReadString('\n')
	if err != nil {
		return ErrBadChunk
	}
	line = strings.TrimRight(line, "\r\n")
	size, ext, _ := strings.Cut(line, ";")
	n, err := strconv.ParseInt(strings.TrimSpace(size), 16, 64)
	if err != nil || n < 0 {
		return ErrBadChunk
	}
	c.sig = ""
	if k, v, ok := strings.Cut(ext, "="); ok && strings.TrimSpace(k) == "chunk-signature" {
		c.sig = strings.TrimSpace(v)
	}
	if c.key != nil && c.sig == "" {
		return ErrBadChunk
	}
	c.remain = n
	c.h = sha256.New()
	return nil
}

func (c *chunkReader) endChunk() error {
	if c.key != nil {
		empty := sha256.Sum256(nil)
		sts := "AWS4-HMAC-SHA256-PAYLOAD\n" + c.stamp + "\n" + c.scope + "\n" + c.prevSig + "\n" +
			hex.EncodeToString(empty[:]) + "\n" + hex.EncodeToString(c.h.Sum(nil))
		want := hex.EncodeToString(hmacSHA256(c.key, sts))
		if subtle.ConstantTimeCompare([]byte(want), []byte(c.sig)) != 1 {
			return errSigMismatch
		}
		c.prevSig = c.sig
	}
	return nil
}

func (c *chunkReader) Read(p []byte) (int, error) {
	for {
		if c.err != nil {
			return 0, c.err
		}
		if c.done {
			return 0, io.EOF
		}
		if c.h == nil { // need a chunk header
			if err := c.header(); err != nil {
				c.err = err
				continue
			}
		}
		if c.remain == 0 {
			if err := c.endChunk(); err != nil {
				c.err = err
				continue
			}
			// final chunk: swallow the optional trailer up to the blank line
			for {
				line, err := c.br.ReadString('\n')
				if strings.TrimRight(line, "\r\n") == "" || err != nil {
					break
				}
			}
			c.done = true
			continue
		}
		if len(p) == 0 {
			return 0, nil
		}
		if int64(len(p)) > c.remain {
			p = p[:c.remain]
		}
		n, err := c.br.Read(p)
		c.h.Write(p[:n])
		c.remain -= int64(n)
		if err == io.EOF {
			err = ErrBadChunk
		}
		if err != nil {
			c.err = err
			if n > 0 {
				return n, nil
			}
			continue
		}
		if c.remain == 0 {
			var crlf [2]byte
			if _, err := io.ReadFull(c.br, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
				c.err = ErrBadChunk
			} else if err := c.endChunk(); err != nil {
				c.err = err
			} else {
				c.h = nil
			}
		}
		return n, nil
	}
}
