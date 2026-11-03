package backup

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func encrypt(t *testing.T, dek, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewEncryptWriter(&buf, dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestEnvelopeRoundTrip(t *testing.T) {
	dek, _ := NewDEK()
	for _, n := range []int{0, 1, 100, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 7} {
		plain := make([]byte, n)
		_, _ = rand.Read(plain)
		ct := encrypt(t, dek, plain)
		if n > 0 && bytes.Contains(ct, plain[:min(n, 64)]) {
			t.Fatalf("n=%d: ciphertext contains plaintext", n)
		}
		got, err := io.ReadAll(NewDecryptReader(bytes.NewReader(ct), dek))
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("n=%d: round trip mismatch", n)
		}
	}
}

func TestEnvelopeDetectsTamperingTruncationAndWrongKey(t *testing.T) {
	dek, _ := NewDEK()
	plain := make([]byte, 2*chunkSize+500)
	_, _ = rand.Read(plain)
	ct := encrypt(t, dek, plain)

	flip := append([]byte(nil), ct...)
	flip[len(flip)/2] ^= 0x01
	if _, err := io.ReadAll(NewDecryptReader(bytes.NewReader(flip), dek)); !errors.Is(err, ErrAuth) {
		t.Fatalf("flipped byte: want ErrAuth, got %v", err)
	}
	hdr := append([]byte(nil), ct...)
	hdr[10] ^= 0x01 // nonce prefix in the header (also the AAD)
	if _, err := io.ReadAll(NewDecryptReader(bytes.NewReader(hdr), dek)); err == nil {
		t.Fatal("tampered header accepted")
	}
	// dropping the final chunk must not look like a clean EOF
	lastLen := 500 + tagLen
	if _, err := io.ReadAll(NewDecryptReader(bytes.NewReader(ct[:len(ct)-lastLen]), dek)); err == nil {
		t.Fatal("truncated stream accepted")
	}
	if _, err := io.ReadAll(NewDecryptReader(bytes.NewReader(ct[:len(ct)-10]), dek)); err == nil {
		t.Fatal("partially truncated stream accepted")
	}
	// reordering chunks
	c1 := ct[headerLen : headerLen+chunkSize+tagLen]
	c2 := ct[headerLen+chunkSize+tagLen : headerLen+2*(chunkSize+tagLen)]
	swapped := append(append(append(append([]byte(nil), ct[:headerLen]...), c2...), c1...), ct[headerLen+2*(chunkSize+tagLen):]...)
	if _, err := io.ReadAll(NewDecryptReader(bytes.NewReader(swapped), dek)); err == nil {
		t.Fatal("reordered chunks accepted")
	}
	other, _ := NewDEK()
	if _, err := io.ReadAll(NewDecryptReader(bytes.NewReader(ct), other)); !errors.Is(err, ErrAuth) {
		t.Fatalf("wrong key: want ErrAuth, got %v", err)
	}
	if _, err := io.ReadAll(NewDecryptReader(strings.NewReader("not a backup at all"), dek)); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestWrapDEK(t *testing.T) {
	dek, _ := NewDEK()
	w, err := WrapDEK(dek, "secret-a")
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapDEK(w, "secret-a")
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := UnwrapDEK(w, "secret-b"); err == nil {
		t.Fatal("unwrapped with the wrong platform secret")
	}
	w2, _ := WrapDEK(dek, "secret-a")
	if w == w2 {
		t.Fatal("wrapping must be randomized")
	}
}

func TestKeysAndSchedule(t *testing.T) {
	pid, rid := uuid.MustParse("11111111-1111-1111-1111-111111111111"), uuid.MustParse("22222222-2222-2222-2222-222222222222")
	ts := time.Date(2026, 11, 2, 7, 0, 0, 0, time.UTC)
	if got, want := ObjectKey(pid, "database", ts, rid, "pgdump"),
		"projects/11111111-1111-1111-1111-111111111111/database/2026-11-02T07:00:00Z-22222222-2222-2222-2222-222222222222.pgdump.enc"; got != want {
		t.Fatalf("key %s != %s", got, want)
	}
	if got := PlatformKey(ts, rid, "files", "tar.gz"); !strings.HasPrefix(got, "platform/2026-11-02T07:00:00Z-") || !strings.HasSuffix(got, ".files.tar.gz.enc") {
		t.Fatalf("platform key %s", got)
	}
	if !strings.HasPrefix(ObjectKey(pid, "manifest", ts, rid, "json"), ProjectPrefix(pid)+"manifest/") {
		t.Fatal("manifest key layout")
	}
	for _, s := range []string{"hourly", "6h", "12h", "daily", "weekly"} {
		if !ValidSchedule(s) {
			t.Errorf("%s should be valid", s)
		}
	}
	if ValidSchedule("monthly") || ValidSchedule("") {
		t.Error("invalid schedule accepted")
	}
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	if !NextRun("daily", nil, now).Equal(now) {
		t.Error("never-run project is due now")
	}
	last := now.Add(-5 * time.Hour)
	if got := NextRun("6h", &last, now); !got.Equal(last.Add(6 * time.Hour)) {
		t.Errorf("6h next run %v", got)
	}
	for _, bad := range []string{"", "1abc", "a-b", "a;drop", "a\"b", strings.Repeat("a", 64)} {
		if ValidTargetName(bad) {
			t.Errorf("target %q accepted", bad)
		}
	}
	if !ValidTargetName("restore_2026") {
		t.Error("good target rejected")
	}
}
