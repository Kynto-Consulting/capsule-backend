package data

import (
	"time"
)

// Redis with TLS from the first byte (rediss://, redis-cli --tls --sni NAME, tls-server-name in the clients that have it)
// needs no new demux code: the connection starts with a ClientHello, kind "tls" reads its SNI, the route table gives the
// service and the "redis" ProtocolHandler (proto_common.go) refuses it if it came the wrong way. Modes:
//   - passthrough: the ClientHello and everything after it go to the Redis server, which must serve TLS itself.
//   - terminate: the gateway terminates TLS with its certificate and speaks clear text to a Redis without TLS.
// Open the port with a listener of kind "tls", for example CAPSULE_GW_LISTEN="[::]:6379=tls".
//
// Clear-text Redis (RESP) is recognised only to be refused politely; it is name-independent, so it leaks nothing.

type redisPlainSniffer struct{}

func (redisPlainSniffer) Kind() Kind { return KindRedisPlain }
func (redisPlainSniffer) Match(b []byte) Match {
	if len(b) == 0 {
		return NeedMore
	}
	if b[0] == '*' { // RESP array: every client command starts this way
		return Matched
	}
	return NoMatch
}

func (s *Server) serveRedisPlain(d *dbState, c *Conn) {
	d.denied.WithLabelValues(protoRedis, "no_tls").Inc()
	c.Ev.Result = "unsupported"
	c.Conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	c.Conn.Write([]byte("-ERR TLS with a server name (SNI) is required; connect with rediss://\r\n"))
	c.Conn.Close()
}
