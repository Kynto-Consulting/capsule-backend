package vpn

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Launch is how the agent starts a kernel based provider inside the tunnel's network namespace.
// Secrets travel in Files (written 0600 in the namespace's private dir), never in argv, so they do not show in `ps`.
type Launch struct {
	Argv  []string          `json:"argv"`
	Files map[string]string `json:"files,omitempty"`
	// AllowCIDRs: the namespace firewall drops everything except these networks (see NamespaceScript).
	AllowCIDRs []string `json:"allow_cidrs"`
}

// RenderLaunch returns the namespace launch plan of a kernel provider. WireGuard does not use it: it runs in
// userspace inside the gateway (netstack) and has no interface or routes on any host.
func RenderLaunch(t Tunnel, secret string) (Launch, error) {
	l := Launch{AllowCIDRs: append([]string(nil), t.CIDRs...)}
	switch t.Provider {
	case ProviderFortiGate:
		var u UserPassSecret
		if err := json.Unmarshal([]byte(secret), &u); err != nil {
			return l, err
		}
		host, port := splitHost(t.Host)
		l.Argv = []string{"openfortivpn", host + ":" + port, "-u", u.Username, "-c", "openfortivpn.conf",
			"--no-routes", "--no-dns", "--pppd-no-peerdns", "--set-routes=0", "--set-dns=0",
			// reconnect by itself when the gateway drops the session (idle timeout, network blip) instead of exiting
			"--persistent=10"}
		if t.CertPin != "" {
			l.Argv = append(l.Argv, "--trusted-cert", t.CertPin)
		}
		l.Files = map[string]string{"openfortivpn.conf": fmt.Sprintf("password = %s\n", u.Password)}
	case ProviderOpenVPN:
		var u UserPassSecret
		if err := json.Unmarshal([]byte(secret), &u); err != nil {
			return l, err
		}
		host, port := splitHost(t.Host)
		var b strings.Builder
		fmt.Fprintf(&b, "client\ndev tun\nproto udp\nremote %s %s\nnobind\npersist-key\npersist-tun\nauth-user-pass auth.txt\n", host, port)
		b.WriteString("route-nopull\npull-filter ignore \"redirect-gateway\"\npull-filter ignore \"dhcp-option\"\npull-filter ignore \"route\"\n")
		for _, c := range t.CIDRs {
			ip, mask := cidrNetmask(c)
			fmt.Fprintf(&b, "route %s %s\n", ip, mask)
		}
		if t.CertPin != "" {
			fmt.Fprintf(&b, "tls-verify-pin %s\n", t.CertPin)
		}
		l.Files = map[string]string{"client.ovpn": b.String(), "auth.txt": u.Username + "\n" + u.Password + "\n"}
		l.Argv = []string{"openvpn", "--config", "client.ovpn"}
	case ProviderIPsec:
		var s IPsecSecret
		if err := json.Unmarshal([]byte(secret), &s); err != nil {
			return l, err
		}
		host, _ := splitHost(t.Host)
		auth := "eap-mschapv2"
		if s.PSK != "" {
			auth = "psk"
		}
		var b strings.Builder
		fmt.Fprintf(&b, "connections {\n  capsule {\n    version = 2\n    remote_addrs = %s\n    local {\n      auth = %s\n", host, auth)
		if s.LocalID != "" {
			fmt.Fprintf(&b, "      id = %s\n", s.LocalID)
		}
		b.WriteString("    }\n    remote {\n      auth = psk\n    }\n    children {\n      capsule {\n")
		fmt.Fprintf(&b, "        remote_ts = %s\n        start_action = start\n        dpd_action = restart\n      }\n    }\n  }\n}\n", strings.Join(t.CIDRs, ","))
		b.WriteString("secrets {\n")
		if s.PSK != "" {
			fmt.Fprintf(&b, "  ike-capsule {\n    secret = %q\n  }\n", s.PSK)
		} else {
			fmt.Fprintf(&b, "  eap-capsule {\n    id = %s\n    secret = %q\n  }\n", s.Username, s.Password)
		}
		b.WriteString("}\n")
		l.Files = map[string]string{"swanctl.conf": b.String()}
		l.Argv = []string{"sh", "-c", "charon & sleep 2; swanctl --load-all; wait"}
	default:
		return l, fmt.Errorf("provider %q runs in userspace and has no namespace launch", t.Provider)
	}
	return l, nil
}

// NamespaceScript is the iptables policy applied inside the namespace: everything dropped except the declared CIDRs
// and the transport to the remote host. Deterministic order for tests.
func NamespaceScript(l Launch, remoteIP string) string {
	var b strings.Builder
	b.WriteString("iptables -P INPUT DROP\niptables -P FORWARD DROP\niptables -P OUTPUT DROP\n")
	b.WriteString("iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n")
	b.WriteString("iptables -A INPUT -i lo -j ACCEPT\niptables -A OUTPUT -o lo -j ACCEPT\n")
	if remoteIP != "" {
		fmt.Fprintf(&b, "iptables -A OUTPUT -d %s -j ACCEPT\n", remoteIP)
	}
	cs := append([]string(nil), l.AllowCIDRs...)
	sort.Strings(cs)
	for _, c := range cs {
		fmt.Fprintf(&b, "iptables -A OUTPUT -d %s -j ACCEPT\n", c)
	}
	return b.String()
}
