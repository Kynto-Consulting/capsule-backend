package webhookout

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// goVerifyExample is the receiver-side check for Go services. It only uses the standard library:
// copy it into your handler. rawBody must be the exact bytes of the request (read them before any
// JSON decoding), and headers the X-Capsule-* values of the request.
func goVerifyExample(secrets []string, timestamp string, signatures []string, rawBody []byte, now time.Time) bool {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || now.Sub(time.Unix(ts, 0)).Abs() > 5*time.Minute {
		return false // malformed or outside the replay window
	}
	ok := false
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		mac := hmac.New(sha256.New, []byte(secret))
		fmt.Fprintf(mac, "%d.", ts)
		mac.Write(rawBody)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		for _, got := range signatures {
			if hmac.Equal([]byte(got), []byte(want)) { // constant time
				ok = true
			}
		}
	}
	return ok
}

type delivery struct {
	secret, prevSecret string
	ts                 int64
	body               []byte
}

func (d delivery) headers() (ts, sig, prevSig string) {
	ts = strconv.FormatInt(d.ts, 10)
	sig = Signature(d.secret, d.ts, d.body)
	if d.prevSecret != "" {
		prevSig = Signature(d.prevSecret, d.ts, d.body)
	}
	return
}

func TestGoVerificationExampleAgreesWithTheSender(t *testing.T) {
	now := time.Now()
	d := delivery{secret: "whsec_current", prevSecret: "whsec_old", ts: now.Unix(), body: []byte(`{"id":"1","event":"pr.merged","data":{}}`)}
	ts, sig, prev := d.headers()
	if !goVerifyExample([]string{d.secret}, ts, []string{sig}, d.body, now) {
		t.Fatal("valid delivery rejected")
	}
	if !goVerifyExample([]string{d.prevSecret}, ts, []string{sig, prev}, d.body, now) {
		t.Fatal("receiver with the old secret must accept through X-Capsule-Signature-Previous")
	}
	if goVerifyExample([]string{d.secret}, ts, []string{sig}, append(d.body, '\n'), now) {
		t.Fatal("tampered body accepted")
	}
	if goVerifyExample([]string{d.secret}, ts, []string{sig}, d.body, now.Add(6*time.Minute)) {
		t.Fatal("replay outside the window accepted")
	}
	if goVerifyExample([]string{"whsec_other"}, ts, []string{sig}, d.body, now) {
		t.Fatal("wrong secret accepted")
	}
	if goVerifyExample([]string{d.secret}, "abc", []string{sig}, d.body, now) {
		t.Fatal("malformed timestamp accepted")
	}
	// the example and the reference Verify must always agree
	for _, skew := range []time.Duration{0, 4 * time.Minute, 6 * time.Minute, -6 * time.Minute} {
		n := now.Add(skew)
		if goVerifyExample([]string{d.secret}, ts, []string{sig}, d.body, n) != Verify([]string{d.secret}, ts, []string{sig}, d.body, n) {
			t.Fatalf("example and Verify disagree at skew %v", skew)
		}
	}
}

// A published signature vector: receivers in any language can check their implementation against it.
func TestSignatureVector(t *testing.T) {
	got := Signature("whsec_test", 1767225600, []byte(`{"hello":"world"}`))
	if !strings.HasPrefix(got, "sha256=") || len(got) != len("sha256=")+64 {
		t.Fatalf("format: %q", got)
	}
	// The expected value is recomputed independently with HMAC from the standard library so the
	// vector documents the construction: HMAC-SHA256(secret, "<timestamp>.<body>").
	mac := hmac.New(sha256.New, []byte("whsec_test"))
	mac.Write([]byte("1767225600.{\"hello\":\"world\"}"))
	if got != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("Signature does not equal HMAC-SHA256(secret, timestamp+\".\"+body): %s", got)
	}
}

func runScript(t *testing.T, name string, args []string, d delivery, now time.Time, mutate func(env map[string]string, body *[]byte)) bool {
	t.Helper()
	ts, sig, prev := d.headers()
	env := map[string]string{
		"CAPSULE_SECRET": d.secret, "CAPSULE_SECRET_PREVIOUS": d.prevSecret,
		"CAPSULE_TIMESTAMP": ts, "CAPSULE_SIGNATURE": sig, "CAPSULE_SIGNATURE_PREVIOUS": prev,
		"CAPSULE_NOW": strconv.FormatInt(now.Unix(), 10),
	}
	body := append([]byte(nil), d.body...)
	if mutate != nil {
		mutate(env, &body)
	}
	cmd := exec.Command(name, args...)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = bytes.NewReader(body)
	err := cmd.Run()
	if err == nil {
		return true
	}
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
		return false
	}
	t.Fatalf("%s %v: %v", name, args, err)
	return false
}

func scriptCases(t *testing.T, run func(d delivery, now time.Time, mutate func(map[string]string, *[]byte)) bool) {
	t.Helper()
	now := time.Now()
	d := delivery{secret: "whsec_current", prevSecret: "whsec_old", ts: now.Unix(),
		body: []byte("{\"id\":\"1\",\"event\":\"pr.merged\",\"data\":{\"title\":\"café \\\"x\\\"\"}}\n")}
	if !run(d, now, nil) {
		t.Error("valid delivery rejected")
	}
	if !run(d, now, func(e map[string]string, _ *[]byte) {
		e["CAPSULE_SECRET"] = "whsec_old"
		e["CAPSULE_SECRET_PREVIOUS"] = ""
	}) {
		t.Error("a receiver that still has the old secret must verify through the previous signature")
	}
	if run(d, now, func(_ map[string]string, b *[]byte) { *b = append(*b, ' ') }) {
		t.Error("tampered body accepted")
	}
	if run(d, now, func(e map[string]string, _ *[]byte) {
		e["CAPSULE_SECRET"] = "whsec_wrong"
		e["CAPSULE_SECRET_PREVIOUS"] = ""
	}) {
		t.Error("wrong secret accepted")
	}
	if run(d, now.Add(10*time.Minute), nil) {
		t.Error("stale timestamp accepted")
	}
	if run(d, now, func(e map[string]string, _ *[]byte) { e["CAPSULE_TIMESTAMP"] = "" }) {
		t.Error("missing timestamp accepted")
	}
}

func TestNodeVerificationExample(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not installed")
	}
	script := filepath.Join("testdata", "verify.js")
	scriptCases(t, func(d delivery, now time.Time, m func(map[string]string, *[]byte)) bool {
		return runScript(t, "node", []string{script}, d, now, m)
	})
}

func TestBashVerificationExample(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not installed")
	}
	script := filepath.ToSlash(filepath.Join("testdata", "verify.sh"))
	scriptCases(t, func(d delivery, now time.Time, m func(map[string]string, *[]byte)) bool {
		return runScript(t, "bash", []string{script}, d, now, m)
	})
}
