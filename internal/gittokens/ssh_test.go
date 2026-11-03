package gittokens_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gitcore"
	"github.com/kynto/capsule/backend/internal/gittokens"
	"github.com/kynto/capsule/backend/internal/gittokens/gittokenstest"
)

func edKey(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " " + comment
}

func rsaKey(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

func TestParsePublicKey(t *testing.T) {
	ed := edKey(t, "me@laptop")
	pk, err := gittokens.ParsePublicKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	if pk.Type != "ssh-ed25519" || !strings.HasPrefix(pk.Fingerprint, "SHA256:") || strings.Contains(pk.Normalized, "me@laptop") {
		t.Fatalf("%+v", pk)
	}
	if pk.Normalized != strings.Join(strings.Fields(ed)[:2], " ") {
		t.Fatal("normalized form is type + base64 (the comment is user text and is dropped)")
	}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	esp, _ := ssh.NewPublicKey(&ec.PublicKey)
	if _, err := gittokens.ParsePublicKey(string(ssh.MarshalAuthorizedKey(esp))); err != nil {
		t.Fatalf("ecdsa must be accepted: %v", err)
	}
	if _, err := gittokens.ParsePublicKey(rsaKey(t, 2048)); err != nil {
		t.Fatalf("rsa 2048 must be accepted: %v", err)
	}

	priv := string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("x")}))
	bad := map[string]string{
		"empty":         "",
		"private key":   priv,
		"garbage":       "hello world",
		"options":       `command="rm -rf /" ` + ed,
		"two keys":      ed + "\n" + edKey(t, "b"),
		"trailing junk": ed + " extra words\nssh-ed25519 AAAA",
		"short rsa":     rsaKey(t, 1024),
		"too long":      "ssh-ed25519 " + strings.Repeat("A", 9000),
	}
	for name, in := range bad {
		if _, err := gittokens.ParsePublicKey(in); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

type keyEnv struct {
	*env
	fj *gittokenstest.ForgejoKeys
}

func newKeyEnv(t *testing.T) *keyEnv {
	e := newEnv(t, gittokens.Config{})
	fj := gittokenstest.NewForgejoKeys()
	e.svc = gittokens.New(gittokens.Config{}, gittokens.Deps{
		Store: e.store, Access: e.access, Directory: &gittokenstest.Directory{Projects: []gittokens.ProjectRef{e.web}},
		Identity: e.ident, Keys: func() gitcore.Keys { return fj }, Now: e.clock.Now, Async: func(f func()) { f() },
	})
	return &keyEnv{e, fj}
}

func TestAddKeySyncsWithForgejoAsTheUser(t *testing.T) {
	e := newKeyEnv(t)
	ctx := context.Background()
	k, err := e.svc.AddKey(ctx, e.bob, "work laptop", edKey(t, "x"), "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if !k.ForgejoSynced() || k.ForgejoKeyID == nil {
		t.Fatalf("key must be synced: %+v", k)
	}
	if !e.fj.Has("bob", k.Fingerprint) {
		t.Fatal("key must exist in Forgejo under the user's login")
	}
	for _, a := range e.fj.Actors {
		if a != "bob" {
			t.Fatalf("every Forgejo call must act as the user (WithActor), got %q", a)
		}
	}
	list, _ := e.svc.ListKeys(ctx, e.bob)
	if len(list) != 1 {
		t.Fatal("list")
	}
	if other, _ := e.svc.ListKeys(ctx, e.carl); len(other) != 0 {
		t.Fatal("keys are per user")
	}
	found := false
	for _, a := range e.store.AuditActions() {
		found = found || a == gittokens.ActionKeyAdd
	}
	if !found {
		t.Fatal("audit")
	}
}

func TestAddKeyRejectsDuplicatesAndBadInput(t *testing.T) {
	e := newKeyEnv(t)
	ctx := context.Background()
	key := edKey(t, "")
	if _, err := e.svc.AddKey(ctx, e.bob, "a", key, ""); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.AddKey(ctx, e.carl, "same key, other user", key, "")
	wantStatus(t, err, http.StatusConflict)
	_, err = e.svc.AddKey(ctx, e.bob, "", edKey(t, ""), "")
	wantStatus(t, err, http.StatusUnprocessableEntity)
	_, err = e.svc.AddKey(ctx, e.bob, "t", "nonsense", "")
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

func TestAddKeyForgejoDownThenReconciles(t *testing.T) {
	e := newKeyEnv(t)
	ctx := context.Background()
	e.fj.Down = true
	k, err := e.svc.AddKey(ctx, e.bob, "k", edKey(t, ""), "")
	if err != nil {
		t.Fatalf("the key is kept even when Forgejo is down: %v", err)
	}
	if k.ForgejoSynced() || k.SyncError == "" || k.SyncAttempts != 1 {
		t.Fatalf("must report unsynced with the reason: %+v", k)
	}
	if strings.Contains(k.SyncError, "token") {
		t.Fatalf("sync error must be safe to show: %q", k.SyncError)
	}
	if n, _ := e.svc.SyncPending(ctx, 10); n != 0 {
		t.Fatal("backoff: nothing is due yet")
	}
	e.fj.Down = false
	e.clock.Advance(2 * time.Minute)
	if n, err := e.svc.SyncPending(ctx, 10); err != nil || n != 1 {
		t.Fatalf("reconcile: n=%d err=%v", n, err)
	}
	if fresh, _ := e.store.GetKey(ctx, k.ID); !fresh.ForgejoSynced() || !e.fj.Has("bob", k.Fingerprint) {
		t.Fatal("key must be registered after the retry")
	}
	if n, _ := e.svc.SyncPending(ctx, 10); n != 0 {
		t.Fatal("nothing pending afterwards")
	}
}

func TestAddKeyAdoptsKeyAlreadyInForgejo(t *testing.T) {
	e := newKeyEnv(t)
	ctx := context.Background()
	key := edKey(t, "")
	pk, _ := gittokens.ParsePublicKey(key)
	e.fj.Keys["bob"] = []gitcore.SSHKey{{ID: 77, Title: "old", Key: pk.Normalized, Fingerprint: pk.Fingerprint}}
	e.fj.AddErr = &gitcore.Error{Code: gitcore.CodeUnprocessed, Message: "key already exists"}
	k, err := e.svc.AddKey(ctx, e.bob, "k", key, "")
	if err != nil {
		t.Fatal(err)
	}
	if !k.ForgejoSynced() || *k.ForgejoKeyID != 77 {
		t.Fatalf("a key that is already in Forgejo is adopted, not an error: %+v", k)
	}
}

func TestAddKeyUserNotInForgejoYet(t *testing.T) {
	e := newKeyEnv(t)
	delete(e.ident.Logins, e.bob)
	k, err := e.svc.AddKey(context.Background(), e.bob, "k", edKey(t, ""), "")
	if err != nil || k.ForgejoSynced() || k.SyncError == "" {
		t.Fatalf("%+v %v", k, err)
	}
}

func TestDeleteKeyRemovesFromForgejoOrRetries(t *testing.T) {
	e := newKeyEnv(t)
	ctx := context.Background()
	k, _ := e.svc.AddKey(ctx, e.bob, "k", edKey(t, ""), "")
	if err := e.svc.DeleteKey(ctx, e.carl, k.ID, ""); err == nil {
		t.Fatal("another user cannot delete the key")
	}
	if err := e.svc.DeleteKey(ctx, e.bob, k.ID, "3.3.3.3"); err != nil {
		t.Fatal(err)
	}
	if e.fj.Has("bob", k.Fingerprint) {
		t.Fatal("the key must be gone from Forgejo")
	}
	if l, _ := e.svc.ListKeys(ctx, e.bob); len(l) != 0 {
		t.Fatal("the key must be gone from the list")
	}
	if err := e.svc.DeleteKey(ctx, e.bob, k.ID, ""); err == nil {
		t.Fatal("deleting twice is not found")
	}

	// Forgejo down while deleting: gone from Capsule at once, removed from Forgejo by the reconciler.
	k2, _ := e.svc.AddKey(ctx, e.bob, "k2", edKey(t, ""), "")
	e.fj.Down = true
	if err := e.svc.DeleteKey(ctx, e.bob, k2.ID, ""); err != nil {
		t.Fatalf("deletion must succeed from the user's point of view: %v", err)
	}
	if l, _ := e.svc.ListKeys(ctx, e.bob); len(l) != 0 {
		t.Fatal("hidden at once")
	}
	if !e.fj.Has("bob", k2.Fingerprint) {
		t.Fatal("still in Forgejo while it is down")
	}
	e.fj.Down = false
	e.clock.Advance(2 * time.Minute)
	if n, _ := e.svc.SyncPending(ctx, 10); n != 1 {
		t.Fatalf("pending removal expected, got %d", n)
	}
	if e.fj.Has("bob", k2.Fingerprint) {
		t.Fatal("the reconciler must remove the key from Forgejo")
	}
	if n, _ := e.svc.SyncPending(ctx, 10); n != 0 {
		t.Fatal("nothing pending afterwards")
	}
}

func TestKeyLimit(t *testing.T) {
	e := newEnv(t, gittokens.Config{MaxSSHKeys: 2})
	for i := 0; i < 2; i++ {
		if _, err := e.svc.AddKey(context.Background(), e.bob, "k", edKey(t, ""), ""); err != nil {
			t.Fatal(err)
		}
	}
	_, err := e.svc.AddKey(context.Background(), e.bob, "k", edKey(t, ""), "")
	wantStatus(t, err, http.StatusUnprocessableEntity)
}

func TestNameRulesMatchOIDC(t *testing.T) {
	// The default resolver must give the login the OIDC provider hands Forgejo as preferred_username.
	users := newFakeUsers()
	id := uuid.New()
	users.m[id] = "Jane.Doe+work@Example.com"
	nr := gittokens.NameRules{Users: users, Taken: fakeTaken{taken: false}}
	got, err := nr.ForgejoLogin(context.Background(), id)
	if err != nil || got != "jane.doe-work" {
		t.Fatalf("%q %v", got, err)
	}
	nr = gittokens.NameRules{Users: users, Taken: fakeTaken{taken: true}}
	got, _ = nr.ForgejoLogin(context.Background(), id)
	want := "jane.doe-work-" + strings.ToLower(hex3(id))
	if got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	if _, err := nr.ForgejoLogin(context.Background(), uuid.New()); err == nil {
		t.Fatal("unknown user")
	}
}
