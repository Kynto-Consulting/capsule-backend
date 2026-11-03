//go:build linux

package data

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Real clients against the in-process gateway: libpq's psql and OpenSSH's ssh (with openssl s_client as ProxyCommand).
// Opt in with CAPSULE_GW_REAL=1. psql needs a reachable PostgreSQL with TLS (CAPSULE_GW_PG_ADDR, default 127.0.0.1:5432),
// a role (CAPSULE_GW_PG_USER / CAPSULE_GW_PG_PASSWORD) and the database "postgres".

func realOnly(t *testing.T) {
	if os.Getenv("CAPSULE_GW_REAL") == "" {
		t.Skip("CAPSULE_GW_REAL not set")
	}
}

func run(t *testing.T, env []string, name string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func TestRealPsqlThroughGateway(t *testing.T) {
	realOnly(t)
	if _, err := exec.LookPath("psql"); err != nil {
		t.Skip("psql not installed")
	}
	pgAddr := os.Getenv("CAPSULE_GW_PG_ADDR")
	if pgAddr == "" {
		pgAddr = "127.0.0.1:5432"
	}
	user, pass := os.Getenv("CAPSULE_GW_PG_USER"), os.Getenv("CAPSULE_GW_PG_PASSWORD")
	if user == "" || pass == "" {
		t.Skip("CAPSULE_GW_PG_USER / CAPSULE_GW_PG_PASSWORD not set")
	}
	g := startGW(t, func(c *Config) { c.Listeners = []ListenerSpec{{Addr: "[::]:0"}} },
		rt("pg", "a.db.test", "postgres", "passthrough", pgAddr))
	_, port := hostPort(g.addr)
	q := "select 'via-gateway' as via, (select ssl from pg_stat_ssl where pid=pg_backend_pid()) as tls, (select coalesce(version,'') from pg_stat_ssl where pid=pg_backend_pid()) as ver"
	conn := func(hostaddr, extra string) []string {
		return []string{fmt.Sprintf("host=a.db.test hostaddr=%s port=%d dbname=postgres user=%s sslmode=require connect_timeout=10 %s", hostaddr, port, user, extra), "-tA", "-F", "|", "-c", q}
	}
	env := []string{"PGPASSWORD=" + pass}
	if v, _ := run(t, nil, "psql", "--version"); true {
		record(t, "psql: %s", v)
	}
	cases := []struct {
		name, hostaddr, extra string
	}{
		{"classic SSLRequest, IPv4", "127.0.0.1", ""},
		{"classic SSLRequest, IPv6 ::1", "::1", ""},
		{"sslnegotiation=direct, IPv4", "127.0.0.1", "sslnegotiation=direct"},
		{"sslnegotiation=direct, IPv6 ::1", "::1", "sslnegotiation=direct"},
	}
	for _, c := range cases {
		out, err := run(t, env, "psql", conn(c.hostaddr, c.extra)...)
		if err != nil || !strings.HasPrefix(out, "via-gateway|t|TLSv1.") {
			t.Fatalf("%s: %v\n%s", c.name, err, out)
		}
		record(t, "psql OK  %-34s -> %s", c.name, out)
	}
	// the gateway must have used the route by SNI, passthrough (the certificate is the backend's)
	if !strings.Contains(g.logs.String(), `"result":"ok"`) {
		t.Fatal("no ok event logged")
	}
	// no SNI (sslsni=0) -> no route -> closed; unknown name -> closed
	for _, bad := range []string{"sslsni=0", "host=unknown.db.test"} {
		args := conn("127.0.0.1", "")
		if strings.HasPrefix(bad, "host=") {
			args[0] = strings.Replace(args[0], "host=a.db.test", bad, 1)
		} else {
			args[0] += " " + bad
		}
		out, err := run(t, env, "psql", args...)
		if err == nil {
			t.Fatalf("%s must not connect: %s", bad, out)
		}
		record(t, "psql refused (%s): %s", bad, firstLine(out))
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func TestRealSSHClientThroughGateway(t *testing.T) {
	realOnly(t)
	for _, b := range []string{"ssh", "openssl"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skip(b + " not installed")
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, signer := mustKey(t)
	scfg := &ssh.ServerConfig{NoClientAuth: true}
	scfg.AddHostKey(signer)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, scfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, rq, _ := nc.Accept()
					go func() {
						for r := range rq {
							if r.Type == "exec" {
								r.Reply(true, nil)
								io.WriteString(ch, "hello-from-sshd-through-capsule\n")
								ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								ch.Close()
							} else {
								r.Reply(false, nil)
							}
						}
					}()
				}
			}()
		}
	}()
	g := startGW(t, func(c *Config) { c.Listeners = []ListenerSpec{{Addr: "[::]:0"}} },
		rt("ssh", "ssh-a.git.test", "ssh", "terminate", ln.Addr().String()))
	_, port := hostPort(g.addr)
	for _, host := range []string{"127.0.0.1", "[::1]"} {
		proxy := fmt.Sprintf("openssl s_client -quiet -connect %s:%d -servername ssh-a.git.test 2>/dev/null", host, port)
		out, err := run(t, nil, "ssh", "-o", "ProxyCommand="+proxy, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
			"-o", "PreferredAuthentications=none", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR", "git@ssh-a.git.test", "whatever")
		if err != nil || !strings.Contains(out, "hello-from-sshd-through-capsule") {
			t.Fatalf("ssh via %s: %v\n%s", host, err, out)
		}
		record(t, "ssh OK  ProxyCommand=openssl s_client via %-10s -> %s", host, firstLine(out))
	}
}
