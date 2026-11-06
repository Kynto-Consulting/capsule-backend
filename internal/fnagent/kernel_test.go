package fnagent

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/fn"
	"github.com/kynto/capsule/backend/internal/vpn"
)

type fakeExec struct{ cmds []string }

func (f *fakeExec) Run(name string, args ...string) error {
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	return nil
}
func (f *fakeExec) Start(dir, name string, args ...string) (func(), error) {
	f.cmds = append(f.cmds, "START "+name+" "+strings.Join(args, " "))
	return func() { f.cmds = append(f.cmds, "STOP") }, nil
}

func TestKernelNamespaceChoreography(t *testing.T) {
	KernelDirRoot = t.TempDir()
	x := &fakeExec{}
	ta := fn.TunnelAssignment{ID: uuid.New(), Provider: vpn.ProviderFortiGate, Host: "161.1.2.3:10443", CIDRs: []string{"10.48.0.0/24"},
		CertPin: strings.Repeat("ab", 32), Secret: `{"username":"ana","password":"s3cr3t-pass"}`}
	k, err := OpenKernel(ta, x)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(x.cmds, "\n")
	for _, want := range []string{"ip netns add capsule-", "iptables -P OUTPUT DROP", "-d 10.48.0.0/24 -j ACCEPT", "START ip netns exec capsule-", "openfortivpn 161.1.2.3:10443", "--no-routes", "route add 161.1.2.3/32"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if strings.Contains(all, "s3cr3t-pass") {
		t.Fatal("password must not appear in any command line")
	}
	if strings.Contains(all, "default") {
		t.Fatal("no default route may be created")
	}
	k.Close()
	if !strings.Contains(strings.Join(x.cmds, "\n"), "ip netns del capsule-") {
		t.Fatal("namespace not deleted on close")
	}
}
