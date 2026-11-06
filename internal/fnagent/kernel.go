package fnagent

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/vpn"
)

// Exec abstracts command execution so the namespace choreography is testable without root.
type Exec interface {
	Run(name string, args ...string) error
	Start(dir string, name string, args ...string) (stop func(), err error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Start runs a long-lived tunnel process (openfortivpn, charon, openvpn). Its output goes to the agent log line by line, so a
// tunnel that dies at once says why (bad credentials, certificate pin, gateway refusal); before, the output was discarded and
// the only symptom was "tunnel interface did not come up" (06-nov-2026). The providers do not print the secrets they read from
// their config file; lines that mention a password are still dropped as a precaution. The exit is logged too.
func (execRunner) Start(dir, name string, args ...string) (func(), error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		return nil, err
	}
	prog := tunnelProgram(args)
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 4096), 64*1024)
		for sc.Scan() {
			if ln := safeTunnelLine(sc.Text()); ln != "" {
				slog.Info("tunnel process", "program", prog, "line", ln)
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		err := cmd.Wait()
		_ = pw.Close()
		slog.Warn("tunnel process exited", "program", prog, "result", fmt.Sprint(err))
		close(done)
	}()
	return func() {
		_ = cmd.Process.Kill()
		<-done
	}, nil
}

// KernelTunnel runs fortigate (openfortivpn), ipsec (strongSwan) or openvpn inside a private network namespace:
// default-DROP firewall, only the declared CIDRs and the remote transport allowed, no host routes, no host DNS,
// nothing listening. Dials happen on a thread that entered the namespace.
type KernelTunnel struct {
	ns    string
	dir   string
	x     Exec
	stop  func()
	start time.Time
	// host rules added by transport (iptables args with -A/-t), removed again on Close
	rules [][]string

	mu     sync.Mutex
	closed bool
}

// KernelDirRoot holds the private (0600) provider config files of each namespace.
var KernelDirRoot = "/run/capsule/ns"

// namespace name is derived from the tunnel id so a crash can be cleaned up on restart.
func nsName(id string) string { return "capsule-" + strings.ReplaceAll(id, "-", "")[:12] }

// OpenKernel builds the namespace, applies the firewall, writes the private config files (0600) and starts the provider.
func OpenKernel(ta fn.TunnelAssignment, x Exec) (*KernelTunnel, error) {
	t := vpn.Tunnel{Provider: ta.Provider, Host: ta.Host, CIDRs: ta.CIDRs, CertPin: ta.CertPin}
	l, err := vpn.RenderLaunch(t, ta.Secret)
	if err != nil {
		return nil, err
	}
	k := &KernelTunnel{ns: nsName(ta.ID.String()), x: x, start: time.Now()}
	k.dir = filepath.Join(KernelDirRoot, k.ns)
	_ = x.Run("ip", "netns", "del", k.ns) // leftovers of a crash
	if err := x.Run("ip", "netns", "add", k.ns); err != nil {
		return nil, err
	}
	fail := func(err error) (*KernelTunnel, error) { k.Close(); return nil, err }
	if err := x.Run("ip", "netns", "exec", k.ns, "ip", "link", "set", "lo", "up"); err != nil {
		return fail(err)
	}
	// Transport to the remote gateway needs a path out of the namespace: a veth pair with NAT is NOT created here;
	// the provider's UDP/TCP socket is created inside the namespace and routed through a veth to the host only for
	// the remote's address (single /32 route, no default route).
	remoteIP := hostIP(ta.Host)
	if err := k.transport(remoteIP); err != nil {
		return fail(err)
	}
	if err := x.Run("ip", "netns", "exec", k.ns, "sh", "-c", vpn.NamespaceScript(l, remoteIP)); err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(k.dir, 0o700); err != nil {
		return fail(err)
	}
	for name, content := range l.Files {
		if err := os.WriteFile(filepath.Join(k.dir, name), []byte(content), 0o600); err != nil {
			return fail(err)
		}
	}
	argv := append([]string{"netns", "exec", k.ns}, l.Argv...)
	stop, err := x.Start(k.dir, "ip", argv...)
	if err != nil {
		return fail(err)
	}
	k.stop = stop
	return k, nil
}

func hostIP(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return ""
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	ips, err := net.LookupIP(h)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}

func (k *KernelTunnel) transport(remoteIP string) error {
	if remoteIP == "" {
		return fmt.Errorf("cannot resolve the remote host")
	}
	host, peer := "cv"+k.ns[8:], "cp"+k.ns[8:]
	for _, c := range [][]string{
		{"ip", "link", "add", host, "type", "veth", "peer", "name", peer},
		{"ip", "link", "set", peer, "netns", k.ns},
		{"ip", "addr", "add", "169.254.77.1/30", "dev", host},
		{"ip", "link", "set", host, "up"},
		{"ip", "netns", "exec", k.ns, "ip", "addr", "add", "169.254.77.2/30", "dev", peer},
		{"ip", "netns", "exec", k.ns, "ip", "link", "set", peer, "up"},
		// one /32 route toward the remote gateway, and nothing else
		{"ip", "netns", "exec", k.ns, "ip", "route", "add", remoteIP + "/32", "via", "169.254.77.1"},
		{"sysctl", "-w", "net.ipv4.conf." + host + ".forwarding=1"},
	} {
		if err := k.x.Run(c[0], c[1:]...); err != nil {
			return err
		}
	}
	for _, r := range transportRules(host, remoteIP) {
		if err := k.x.Run("iptables", r...); err != nil {
			return err
		}
		k.rules = append(k.rules, r)
	}
	return nil
}

// transportRules are the host rules of a tunnel namespace: NAT of the namespace address toward the remote gateway only, forward
// of that traffic, and of its answers back. The answers rule was missing: with Docker on the node the FORWARD policy is DROP, so
// the gateway's SYN-ACK was dropped and openfortivpn ended with "connect: Connection timed out" (06-nov-2026, first real FortiGate).
// The rules are inserted (-I) so they run before Docker's chains, and Close removes exactly these (before, every reconnect left
// a duplicate set behind).
func transportRules(host, remoteIP string) [][]string {
	return [][]string{
		{"-t", "nat", "-I", "POSTROUTING", "-s", "169.254.77.2/32", "-d", remoteIP + "/32", "-j", "MASQUERADE"},
		{"-I", "FORWARD", "-i", host, "-j", "DROP"},
		{"-I", "FORWARD", "-i", host, "-d", remoteIP + "/32", "-j", "ACCEPT"},
		{"-I", "FORWARD", "-o", host, "-s", remoteIP + "/32", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
	}
}

// deleteRule turns an insert rule (-I CHAIN ...) into its delete (-D CHAIN ...).
func deleteRule(r []string) []string {
	out := append([]string(nil), r...)
	for i, a := range out {
		if a == "-I" || a == "-A" {
			out[i] = "-D"
			break
		}
	}
	return out
}

// Health: up when a non-loopback tunnel interface other than the transport veth exists in the namespace.
func (k *KernelTunnel) Health() (string, time.Time, string) {
	out, err := exec.Command("ip", "-o", "netns", "exec", k.ns, "ip", "-o", "link", "show").Output()
	if err != nil {
		return vpn.StatusError, time.Time{}, "namespace not reachable"
	}
	for _, ln := range strings.Split(string(out), "\n") {
		for _, p := range []string{"tun", "ppp", "xfrm", "ipsec"} {
			if strings.Contains(ln, ": "+p) {
				return vpn.StatusUp, time.Now(), ""
			}
		}
	}
	if time.Since(k.start) > 90*time.Second {
		return vpn.StatusError, time.Time{}, "tunnel interface did not come up"
	}
	return vpn.StatusConnecting, time.Time{}, "negotiating"
}

// Close kills the provider and deletes the namespace, the veth and the NAT rules.
func (k *KernelTunnel) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return
	}
	k.closed = true
	if k.stop != nil {
		k.stop()
	}
	_ = k.x.Run("ip", "netns", "del", k.ns)
	for i := len(k.rules) - 1; i >= 0; i-- {
		_ = k.x.Run("iptables", deleteRule(k.rules[i])...)
	}
	k.rules = nil
	_ = os.RemoveAll(k.dir)
}

// tunnelProgram names the provider behind `ip netns exec <ns> <program> ...` for the log.
func tunnelProgram(args []string) string {
	if len(args) >= 4 && args[0] == "netns" && args[1] == "exec" {
		return filepath.Base(args[3])
	}
	if len(args) > 0 {
		return filepath.Base(args[0])
	}
	return ""
}

// safeTunnelLine trims a provider output line for the log and drops anything that could carry a secret.
func safeTunnelLine(s string) string {
	s = strings.TrimSpace(s)
	l := strings.ToLower(s)
	for _, w := range []string{"password", "passwd", "secret", "psk", "cookie", "svpncookie"} {
		if strings.Contains(l, w) {
			return ""
		}
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
