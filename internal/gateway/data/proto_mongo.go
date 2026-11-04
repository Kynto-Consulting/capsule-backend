package data

import (
	"encoding/binary"
)

// MongoDB with TLS from the first byte (tls=true in the URI, mongosh --tls) is routed by SNI like any TLS connection:
// kind "tls", route table, "mongo" ProtocolHandler (proto_common.go). Mode passthrough: the Mongo server terminates TLS
// itself (--tlsMode requireTLS). Mode terminate also works (clear text to the server) but is not what the plan offers.
// Open the port with a listener of kind "tls", for example CAPSULE_GW_LISTEN="[::]:27017=tls".
//
// A clear-text MongoDB message is recognised only to be refused: the wire header is 16 bytes (int32 LE messageLength,
// requestID, responseTo, opCode) and a client opens with OP_MSG (2013) or, for the legacy handshake, OP_QUERY (2004).

const (
	mongoOpQuery   = 2004
	mongoOpMsg     = 2013
	mongoMaxMsg    = 48_000_000 // the server's own maxMessageSizeBytes
	mongoHeaderLen = 16
)

// parseMongoHeader validates the first 16 bytes of a clear-text MongoDB connection.
func parseMongoHeader(b []byte) (length, opcode int32, ok bool) {
	if len(b) < mongoHeaderLen {
		return 0, 0, false
	}
	length = int32(binary.LittleEndian.Uint32(b[0:4]))
	opcode = int32(binary.LittleEndian.Uint32(b[12:16]))
	if length < mongoHeaderLen || length > mongoMaxMsg {
		return 0, 0, false
	}
	if opcode != mongoOpMsg && opcode != mongoOpQuery {
		return 0, 0, false
	}
	return length, opcode, true
}

type mongoPlainSniffer struct{}

func (mongoPlainSniffer) Kind() Kind { return KindMongoPlain }
func (mongoPlainSniffer) Match(b []byte) Match {
	// messageLength is little-endian and at most 48 MB: its top byte is 0..2
	if len(b) >= 4 && b[3] > 0x02 {
		return NoMatch
	}
	if len(b) < mongoHeaderLen {
		return NeedMore
	}
	if _, _, ok := parseMongoHeader(b); ok {
		return Matched
	}
	return NoMatch
}

func (s *Server) serveMongoPlain(d *dbState, c *Conn) {
	d.denied.WithLabelValues(protoMongo, "no_tls").Inc()
	c.Ev.Result = "unsupported"
	c.Conn.Close()
}
