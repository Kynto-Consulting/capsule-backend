package sftpd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The real OpenSSH `sftp` client against the server: public key login, mkdir, put, ls, get, rename, rm, rmdir
// and a resumed upload (reput). Skipped where the sftp binary is not installed.
func TestOpenSSHSftpClient(t *testing.T) {
	bin, err := exec.LookPath("sftp")
	if err != nil {
		t.Skip("OpenSSH sftp client not installed")
	}
	r := newRig(t, nil)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	r.auth.keys["alpha-files"] = []AuthorizedKey{{ID: "k1", Key: sp}}
	dir := t.TempDir()
	blk, _ := ssh.MarshalPrivateKey(priv, "")
	keyFile := filepath.Join(dir, "id")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 5<<20)
	rand.Read(data)
	local := filepath.ToSlash(filepath.Join(dir, "up.bin"))
	os.WriteFile(local, data, 0o644)
	back := filepath.ToSlash(filepath.Join(dir, "down.bin"))

	host, port, _ := net.SplitHostPort(r.addr)
	run := func(script string) string {
		t.Helper()
		batch := filepath.Join(dir, "batch")
		os.WriteFile(batch, []byte(script), 0o600)
		var out bytes.Buffer
		c := exec.Command(bin, "-i", keyFile, "-P", port, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
			"-o", "IdentitiesOnly=yes", "-b", batch, "alpha-files@"+host)
		c.Stdout, c.Stderr = &out, &out
		if err := c.Run(); err != nil {
			t.Fatalf("sftp failed: %v\n%s", err, out.String())
		}
		return out.String()
	}
	out := run("mkdir /in\nput " + local + " /in/up.bin\nls -l /in\n")
	if !strings.Contains(out, "up.bin") {
		t.Fatalf("ls does not show the upload:\n%s", out)
	}
	run("get /in/up.bin " + back + "\n")
	got, _ := os.ReadFile(back)
	if !bytes.Equal(got, data) {
		t.Fatal("downloaded file differs")
	}
	// resume: cut the remote object to half through the engine, then reput finishes it
	half := int64(len(data) / 2)
	run("rm /in/up.bin\n")
	if _, err := r.st.PutEmpty("alpha-files", "in/up.bin", ""); err != nil {
		t.Fatal(err)
	}
	cut := filepath.ToSlash(filepath.Join(dir, "cut.bin"))
	os.WriteFile(cut, data[:half], 0o644)
	run("put " + cut + " /in/up.bin\n")
	run("reput " + local + " /in/up.bin\n")
	o, err := r.st.Stat("alpha-files", "in/up.bin")
	if err != nil || o.Size != int64(len(data)) {
		t.Fatalf("after reput: %+v %v", o, err)
	}
	run("get /in/up.bin " + back + "\n")
	if got, _ = os.ReadFile(back); !bytes.Equal(got, data) {
		t.Fatal("resumed file differs")
	}
	run("rename /in/up.bin /in/moved.bin\nrm /in/moved.bin\nrmdir /in\n")
	if r.st.Count("alpha-files") != 0 {
		t.Fatalf("objects left: %d", r.st.Count("alpha-files"))
	}
}

// scp in SFTP mode (-s, the default since OpenSSH 9) uses the same subsystem.
func TestOpenSSHScp(t *testing.T) {
	bin, err := exec.LookPath("scp")
	if err != nil {
		t.Skip("OpenSSH scp not installed")
	}
	r := newRig(t, nil)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	r.auth.keys["alpha-files"] = []AuthorizedKey{{ID: "k1", Key: sp}}
	dir := t.TempDir()
	blk, _ := ssh.MarshalPrivateKey(priv, "")
	keyFile := filepath.Join(dir, "id")
	os.WriteFile(keyFile, pem.EncodeToMemory(blk), 0o600)
	local := filepath.Join(dir, "a.txt")
	os.WriteFile(local, []byte("via scp"), 0o644)
	host, port, _ := net.SplitHostPort(r.addr)
	args := func(a ...string) []string {
		return append([]string{"-s", "-i", keyFile, "-P", port, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "IdentitiesOnly=yes"}, a...)
	}
	if out, err := exec.Command(bin, args(local, "alpha-files@"+host+":/a.txt")...).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "unknown option") || strings.Contains(string(out), "illegal option") {
			t.Skip("scp without -s: too old")
		}
		t.Fatalf("scp upload: %v\n%s", err, out)
	}
	back := filepath.Join(dir, "b.txt")
	if out, err := exec.Command(bin, args("alpha-files@"+host+":/a.txt", back)...).CombinedOutput(); err != nil {
		t.Fatalf("scp download: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(back); string(b) != "via scp" {
		t.Fatalf("got %q", b)
	}
}
