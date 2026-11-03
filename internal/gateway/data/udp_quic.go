package data

// QUIC datagrams (capsule/1 transport 3, PROTOCOL.md 10.6): NOT IMPLEMENTED and not tested. The gateway answers
// transport 3 with status 1 / code 0x0109 (see serveTunnel). This file records the seam so the work is bounded.
//
// What exists for it:
//   - datagramConn (udp_session.go) is the client side of a UDP session. runUDPSession is transport agnostic.
//   - The destination side (connected UDP socket, limits, metrics, idle clock) is shared.
//
// What a QUIC transport must add (TODO, requires a QUIC library such as quic-go and UDP/443 open in the security
// group, neither present today):
//  1. A listener on UDP/443 with ALPN "capsule/1" and RFC 9221 datagrams enabled.
//  2. Control stream (id 0) carrying the same CAP1 header and CAPR with transport = 3; CAPR.status = 0 creates the
//     session and returns session_id.
//  3. A datagramConn whose ReadDatagram strips the 8-byte session_id prefix from each QUIC datagram (payload at most
//     1200-8 bytes), WriteDatagram prepends it, WriteKeepalive is a no-op (QUIC PING does the job), Interrupt closes
//     the read side and Close closes the connection with an application error code 0.
//  4. Admission identical to serveTunnel (authorisation, limits, route lookup), then runUDPSession.
//  5. Connection migration needs no code here: the session is bound to the QUIC connection id, not to an address.
//
// Until then, QUICDatagramsAvailable stays false and operators must not advertise transport 3.
const QUICDatagramsAvailable = false
