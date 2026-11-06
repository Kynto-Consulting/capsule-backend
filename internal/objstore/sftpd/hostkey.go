// Package sftpd is the SFTP front end of Capsule's own object store: an SSH server (golang.org/x/crypto/ssh) that
// speaks only the sftp subsystem (github.com/pkg/sftp request server) over one bucket seen as a tree of folders.
//
// It has no shell, no exec, no port forwarding and no agent forwarding, never touches the host file system
// (objects are addressed by key, the path is only a string), and shares the S3 engine's atomic quota
// reservations. It listens on an internal port only: the Capsule gateway (capsule://project/sftp) and apps of
// the same server (host.docker.internal:<port>) reach it.
package sftpd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// LoadOrCreateHostKey returns the persistent ed25519 host key stored at path, creating it (mode 0600) on the
// first start. It lives in the object store volume, so it survives restarts and redeploys: clients never see a
// host key change.
func LoadOrCreateHostKey(path string) (ssh.Signer, error) {
	if raw, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(raw)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "capsule-objstore-sftp")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pem.EncodeToMemory(blk), 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, fmt.Errorf("storing host key: %w", err)
	}
	return ssh.NewSignerFromKey(priv)
}

// Fingerprint is the SHA256 fingerprint of the host key, as `ssh-keygen -l` prints it.
func Fingerprint(s ssh.Signer) string { return ssh.FingerprintSHA256(s.PublicKey()) }
