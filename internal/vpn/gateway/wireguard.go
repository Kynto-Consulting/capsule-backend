package gateway

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/kynto/capsule/backend/internal/vpn"
)

// WireGuardTunnel is a userspace WireGuard tunnel (wireguard-go + gVisor netstack): no network interface, no host
// routes, no host DNS change, and nothing can reach the process through it except traffic from the configured peer.
type WireGuardTunnel struct {
	dev *device.Device
	net *netstack.Net
}

// WGParams are the already decoded parameters.
type WGParams struct {
	Secret     vpn.WGSecret
	Endpoint   string       // host:port of the remote peer
	AllowedIPs []string     // the declared CIDRs
	ListenPort int          // 0 = ephemeral; only the peer's key is accepted
	MTU        int          // 0 = 1380
	Logf       func(string) // already redacted by the caller
}

func b64hex(k string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("invalid wireguard key")
	}
	return hex.EncodeToString(b), nil
}

// StartWireGuard opens the tunnel.
func StartWireGuard(p WGParams) (*WireGuardTunnel, error) {
	addr, err := netip.ParsePrefix(p.Secret.Address)
	if err != nil {
		return nil, err
	}
	mtu := p.MTU
	if mtu == 0 {
		mtu = 1380
	}
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr.Addr()}, nil, mtu)
	if err != nil {
		return nil, err
	}
	logger := device.NewLogger(device.LogLevelError, "wg ")
	if p.Logf != nil {
		logger = &device.Logger{
			Verbosef: func(string, ...any) {},
			Errorf:   func(f string, a ...any) { p.Logf(fmt.Sprintf(f, a...)) },
		}
	}
	d := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	priv, err := b64hex(p.Secret.PrivateKey)
	if err != nil {
		d.Close()
		return nil, err
	}
	pub, err := b64hex(p.Secret.PeerPublicKey)
	if err != nil {
		d.Close()
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\nlisten_port=%d\npublic_key=%s\n", priv, p.ListenPort, pub)
	if p.Secret.PresharedKey != "" {
		psk, err := b64hex(p.Secret.PresharedKey)
		if err != nil {
			d.Close()
			return nil, err
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	ep, err := resolveEndpoint(p.Endpoint)
	if err != nil {
		d.Close()
		return nil, err
	}
	ka := p.Secret.Keepalive
	if ka == 0 {
		ka = 25
	}
	fmt.Fprintf(&b, "endpoint=%s\npersistent_keepalive_interval=%d\nreplace_allowed_ips=true\n", ep, ka)
	for _, c := range p.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", c)
	}
	if err := d.IpcSet(b.String()); err != nil {
		d.Close()
		return nil, err
	}
	if err := d.Up(); err != nil {
		d.Close()
		return nil, err
	}
	return &WireGuardTunnel{dev: d, net: tnet}, nil
}

func resolveEndpoint(hp string) (string, error) {
	ap, err := netip.ParseAddrPort(hp)
	if err == nil {
		return ap.String(), nil
	}
	host, port, err := net.SplitHostPort(hp)
	if err != nil {
		return "", err
	}
	ips, err := net.LookupIP(host) // the transport endpoint is resolved by the gateway process, not through the tunnel
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("cannot resolve %s", host)
	}
	a, _ := netip.AddrFromSlice(ips[0])
	pn, _ := net.LookupPort("udp", port)
	return netip.AddrPortFrom(a.Unmap(), uint16(pn)).String(), nil
}

// DialContext implements Dialer: only traffic inside the tunnel.
func (w *WireGuardTunnel) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return w.net.DialContext(ctx, network, addr)
}

// LastHandshake returns the time of the last completed handshake with the peer (zero if none yet).
func (w *WireGuardTunnel) LastHandshake() time.Time {
	out, err := w.dev.IpcGet()
	if err != nil {
		return time.Time{}
	}
	var sec, nsec int64
	for _, ln := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(ln, "last_handshake_time_sec="); ok {
			fmt.Sscan(v, &sec)
		}
		if v, ok := strings.CutPrefix(ln, "last_handshake_time_nsec="); ok {
			fmt.Sscan(v, &nsec)
		}
	}
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, nsec)
}

// ListenPort returns the UDP port the device bound.
func (w *WireGuardTunnel) ListenPort() int {
	out, _ := w.dev.IpcGet()
	for _, ln := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(ln, "listen_port="); ok {
			var n int
			fmt.Sscan(v, &n)
			return n
		}
	}
	return 0
}

// Close tears the tunnel down.
func (w *WireGuardTunnel) Close() { w.dev.Close() }
