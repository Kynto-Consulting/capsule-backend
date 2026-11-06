package gateway

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
)

// SocksDial connects to target ("ip:port") through the SOCKS5 endpoint at proxyNet/proxyAddr.
func SocksDial(ctx context.Context, proxyNet, proxyAddr, target string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, proxyNet, proxyAddr)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) { _ = c.Close(); return nil, err }
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil || rep[0] != 5 || rep[1] != 0 {
		return fail(fmt.Errorf("socks: handshake refused"))
	}
	ap, err := netip.ParseAddrPort(target)
	if err != nil {
		return fail(err)
	}
	req := []byte{5, 1, 0}
	if ap.Addr().Is4() {
		a := ap.Addr().As4()
		req = append(req, 1)
		req = append(req, a[:]...)
	} else {
		a := ap.Addr().As16()
		req = append(req, 4)
		req = append(req, a[:]...)
	}
	req = binary.BigEndian.AppendUint16(req, ap.Port())
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil {
		return fail(err)
	}
	if resp[1] != 0 {
		return fail(fmt.Errorf("socks: connect refused (code %d)", resp[1]))
	}
	return c, nil
}
