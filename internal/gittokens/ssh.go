package gittokens

import (
	"context"
	"crypto/rsa"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/gitcore"
)

// ParsedKey is a validated public key.
type ParsedKey struct {
	Type        string // e.g. ssh-ed25519
	Normalized  string // "<type> <base64>" (the comment is dropped: it is user text going to Forgejo)
	Fingerprint string // SHA256:... (the format Forgejo reports)
}

const (
	maxKeyLen    = 8192
	minRSABits   = 2048
	syncMaxDelay = time.Hour
)

var allowedKeyTypes = map[string]bool{
	ssh.KeyAlgoED25519:    true,
	ssh.KeyAlgoSKED25519:  true,
	ssh.KeyAlgoECDSA256:   true,
	ssh.KeyAlgoECDSA384:   true,
	ssh.KeyAlgoECDSA521:   true,
	ssh.KeyAlgoSKECDSA256: true,
	ssh.KeyAlgoRSA:        true,
}

// ParsePublicKey validates one OpenSSH public key line. It rejects private keys, authorized_keys
// options (command=..., from=...), several keys, DSA and RSA below 2048 bits.
func ParsePublicKey(line string) (*ParsedKey, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, errInvalid("key is required")
	}
	if len(line) > maxKeyLen {
		return nil, errInvalid("key is too long")
	}
	if strings.Contains(line, "PRIVATE KEY") {
		return nil, errInvalid("this looks like a private key; paste the public key (.pub) instead")
	}
	if strings.ContainsAny(line, "\r\n") {
		return nil, errInvalid("paste exactly one public key")
	}
	pub, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, errInvalid("not a valid OpenSSH public key")
	}
	if len(options) > 0 {
		return nil, errInvalid("key options are not allowed")
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return nil, errInvalid("paste exactly one public key")
	}
	if !allowedKeyTypes[pub.Type()] {
		return nil, errInvalid("key type " + pub.Type() + " is not supported (use ed25519, ecdsa or rsa >= 2048)")
	}
	if pub.Type() == ssh.KeyAlgoRSA {
		if cp, ok := pub.(ssh.CryptoPublicKey); ok {
			if k, ok := cp.CryptoPublicKey().(*rsa.PublicKey); ok && k.N.BitLen() < minRSABits {
				return nil, errInvalid("RSA keys must have at least 2048 bits")
			}
		}
	}
	return &ParsedKey{
		Type:        pub.Type(),
		Normalized:  strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		Fingerprint: ssh.FingerprintSHA256(pub),
	}, nil
}

func cleanTitle(t string) (string, error) {
	t = strings.TrimSpace(t)
	if n := len([]rune(t)); n < 1 || n > 100 {
		return "", errInvalid("title must have 1 to 100 characters")
	}
	for _, r := range t {
		if unicode.IsControl(r) {
			return "", errInvalid("title must not contain control characters")
		}
	}
	return t, nil
}

// ListKeys returns the user's live keys.
func (s *Service) ListKeys(ctx context.Context, userID uuid.UUID) ([]*SSHKey, error) {
	return s.d.Store.ListKeys(ctx, userID)
}

// AddKey stores the key and registers it in Forgejo acting as the user. If Forgejo is not
// reachable (or the user has no Forgejo account yet) the key is kept with forgejo_synced=false and
// the reconciler retries; the call still succeeds.
func (s *Service) AddKey(ctx context.Context, userID uuid.UUID, title, key, ip string) (*SSHKey, error) {
	title, err := cleanTitle(title)
	if err != nil {
		return nil, err
	}
	pk, err := ParsePublicKey(key)
	if err != nil {
		return nil, err
	}
	existing, err := s.d.Store.ListKeys(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(existing) >= s.cfg.MaxSSHKeys {
		return nil, errLimit("too many SSH keys; delete one first")
	}
	k, err := s.d.Store.CreateKey(ctx, &SSHKey{UserID: userID, Title: title, PublicKey: pk.Normalized, KeyType: pk.Type, Fingerprint: pk.Fingerprint, NextSyncAt: s.now()})
	if errors.Is(err, domain.ErrConflict) {
		return nil, errConflict("this key is already registered")
	}
	if err != nil {
		return nil, err
	}
	s.syncKey(ctx, k)
	s.recordAudit(ctx, AuditRecord{UserID: userID, Action: ActionKeyAdd, ResourceType: "git_ssh_key", ResourceID: k.ID, IP: ip,
		Meta: map[string]any{"fingerprint": k.Fingerprint, "type": k.KeyType}})
	if fresh, err := s.d.Store.GetKey(ctx, k.ID); err == nil {
		return fresh, nil
	}
	return k, nil
}

// DeleteKey removes the key from Capsule at once (it disappears from lists) and from Forgejo; if
// Forgejo cannot be reached the removal is retried by the reconciler.
func (s *Service) DeleteKey(ctx context.Context, userID, keyID uuid.UUID, ip string) error {
	k, err := s.d.Store.GetKey(ctx, keyID)
	if err != nil {
		return mapNotFound(err, "key")
	}
	if k.UserID != userID || k.DeletedAt != nil {
		return errNotFound("key not found")
	}
	if err := s.d.Store.SoftDeleteKey(ctx, k.ID, s.now()); err != nil {
		return err
	}
	k.DeletedAt = ptrTime(s.now())
	s.unsyncKey(ctx, k)
	s.recordAudit(ctx, AuditRecord{UserID: userID, Action: ActionKeyDelete, ResourceType: "git_ssh_key", ResourceID: k.ID, IP: ip,
		Meta: map[string]any{"fingerprint": k.Fingerprint}})
	return nil
}

func ptrTime(t time.Time) *time.Time { return &t }

func (s *Service) forgejoKeys() gitcore.Keys {
	if s.d.Keys == nil {
		return nil
	}
	return s.d.Keys()
}

func (s *Service) backoff(attempts int) time.Time {
	d := 30 * time.Second
	for i := 0; i < attempts && d < syncMaxDelay; i++ {
		d *= 2
	}
	if d > syncMaxDelay {
		d = syncMaxDelay
	}
	return s.now().Add(d)
}

func safeMsg(err error) string {
	msg := err.Error()
	if e, ok := gitcore.AsError(err); ok {
		msg = string(e.Code) + ": " + e.Message
	}
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// syncKey registers a live key in Forgejo as the user and records the result.
func (s *Service) syncKey(ctx context.Context, k *SSHKey) {
	fail := func(err error) {
		if e := s.d.Store.MarkKeySyncFailed(ctx, k.ID, safeMsg(err), s.backoff(k.SyncAttempts+1)); e != nil {
			s.log().Warn("git keys: recording sync failure failed", "error", e.Error())
		}
	}
	kc := s.forgejoKeys()
	if kc == nil {
		fail(errors.New("forgejo integration unavailable"))
		return
	}
	login, err := s.d.Identity.ForgejoLogin(ctx, k.UserID)
	if err != nil {
		fail(err)
		return
	}
	actx := gitcore.WithActor(ctx, login)
	created, err := kc.AddSSHKey(actx, k.Title, k.PublicKey, false)
	if err != nil {
		// The key may already be in Forgejo from a previous half-finished attempt: adopt it.
		if list, lerr := kc.ListSSHKeys(actx); lerr == nil {
			for _, fk := range list {
				if fk.Fingerprint == k.Fingerprint {
					if e := s.d.Store.MarkKeySynced(ctx, k.ID, fk.ID); e != nil {
						s.log().Warn("git keys: recording sync failed", "error", e.Error())
					}
					return
				}
			}
		}
		fail(err)
		return
	}
	if e := s.d.Store.MarkKeySynced(ctx, k.ID, created.ID); e != nil {
		s.log().Warn("git keys: recording sync failed", "error", e.Error())
	}
}

// unsyncKey removes a deleted key from Forgejo (as the user) and records the result.
func (s *Service) unsyncKey(ctx context.Context, k *SSHKey) {
	if k.ForgejoKeyID == nil {
		return
	}
	fail := func(err error) {
		if e := s.d.Store.MarkKeySyncFailed(ctx, k.ID, safeMsg(err), s.backoff(k.SyncAttempts+1)); e != nil {
			s.log().Warn("git keys: recording removal failure failed", "error", e.Error())
		}
	}
	kc := s.forgejoKeys()
	if kc == nil {
		fail(errors.New("forgejo integration unavailable"))
		return
	}
	login, err := s.d.Identity.ForgejoLogin(ctx, k.UserID)
	if err != nil {
		fail(err)
		return
	}
	err = kc.DeleteSSHKey(gitcore.WithActor(ctx, login), *k.ForgejoKeyID)
	if err != nil && !errors.Is(err, gitcore.ErrNotFound) {
		fail(err)
		return
	}
	if e := s.d.Store.MarkKeyRemoved(ctx, k.ID); e != nil {
		s.log().Warn("git keys: recording removal failed", "error", e.Error())
	}
}

// SyncPending retries pending creations and removals that are due. It returns how many keys it handled.
func (s *Service) SyncPending(ctx context.Context, limit int) (int, error) {
	if limit <= 0 {
		limit = 50
	}
	keys, err := s.d.Store.ListPendingKeys(ctx, s.now(), limit)
	if err != nil {
		return 0, err
	}
	for _, k := range keys {
		if k.DeletedAt != nil {
			s.unsyncKey(ctx, k)
		} else {
			s.syncKey(ctx, k)
		}
	}
	return len(keys), nil
}
