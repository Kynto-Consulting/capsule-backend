package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/kynto/capsule/backend/internal/authz"
	"github.com/kynto/capsule/backend/internal/objstore"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// SFTPInfo is what a client needs to know about the SFTP front end of the object store.
type SFTPInfo struct {
	InternalAddr string // host.docker.internal:2222: for apps of the same server
	Fingerprint  string // SHA256 fingerprint of the server's host key
}

type sftpView struct {
	User         string `json:"user"`          // the bucket name
	GatewayURI   string `json:"gateway_uri"`   // capsule://<project>/sftp
	InternalAddr string `json:"internal_addr"` // host:port reachable from apps of the same server
	Fingerprint  string `json:"host_key_fingerprint"`
	Command      string `json:"command"` // sftp through the gateway
}

func (h *StorageHandler) sftpView(rec *objstore.BucketRecord, slug string) *sftpView {
	if h.obj == nil || h.obj.SFTP == nil {
		return nil
	}
	return &sftpView{User: rec.Bucket, GatewayURI: "capsule://" + slug + "/sftp", InternalAddr: h.obj.SFTP.InternalAddr, Fingerprint: h.obj.SFTP.Fingerprint,
		Command: fmt.Sprintf("capsule ssh %s/sftp -l %s -s sftp", slug, rec.Bucket)}
}

type sshKeyView struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Fingerprint string  `json:"fingerprint"`
	PublicKey   string  `json:"public_key"`
	CreatedAt   string  `json:"created_at"`
	LastUsedAt  *string `json:"last_used_at,omitempty"`
}

func keyView(k *objstore.SSHKeyRecord) sshKeyView {
	v := sshKeyView{ID: k.ID.String(), Name: k.Name, Fingerprint: k.Fingerprint, PublicKey: k.PublicKey, CreatedAt: k.CreatedAt.UTC().Format(time.RFC3339)}
	if k.LastUsedAt != nil {
		s := k.LastUsedAt.UTC().Format(time.RFC3339)
		v.LastUsedAt = &s
	}
	return v
}

const maxSSHKeysPerBucket = 20

// ParseSSHKey validates a public key line (authorized_keys format) and returns its canonical form, fingerprint and
// comment. Certificates and RSA keys under 2048 bits are refused.
func ParseSSHKey(line string) (canonical, fingerprint, comment string, err error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsAny(line, "\r\n") || len(line) > 8192 {
		return "", "", "", errors.New("provide one public key on one line (ssh-ed25519 AAAA… comment)")
	}
	pk, comment, opts, _, perr := ssh.ParseAuthorizedKey([]byte(line))
	if perr != nil || len(opts) > 0 {
		return "", "", "", errors.New("not a valid public key (options such as command= are not allowed)")
	}
	if strings.Contains(pk.Type(), "-cert-") {
		return "", "", "", errors.New("certificates are not supported: register the public key")
	}
	if ck, ok := pk.(ssh.CryptoPublicKey); ok {
		if rk, ok := ck.CryptoPublicKey().(interface{ Size() int }); ok && pk.Type() == ssh.KeyAlgoRSA && rk.Size()*8 < 2048 {
			return "", "", "", errors.New("RSA keys must be at least 2048 bits")
		}
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))), ssh.FingerprintSHA256(pk), comment, nil
}

// ListSSHKeys: GET .../storage/{dbID}/ssh-keys
func (h *StorageHandler) ListSSHKeys(w http.ResponseWriter, r *http.Request) {
	_, rec, _, ok := h.loadObjstore(w, r, authz.ProjectRead)
	if !ok {
		return
	}
	keys, err := h.obj.Repo.ListSSHKeys(r.Context(), rec.Bucket)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list SSH keys")
		return
	}
	out := make([]sshKeyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, keyView(k))
	}
	respondJSON(w, http.StatusOK, map[string]any{"data": out})
}

// AddSSHKey: POST .../storage/{dbID}/ssh-keys {name?, public_key}
func (h *StorageHandler) AddSSHKey(w http.ResponseWriter, r *http.Request) {
	_, rec, project, ok := h.loadObjstore(w, r, authz.ProjectDatabases)
	if !ok {
		return
	}
	var req struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	canonical, fp, comment, err := ParseSSHKey(req.PublicKey)
	if err != nil {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = comment
	}
	if name == "" {
		name = "key-" + strings.TrimPrefix(fp, "SHA256:")[:8]
	}
	if len(name) > 64 || strings.ContainsAny(name, "\r\n\t") {
		respondError(w, http.StatusBadRequest, "VALIDATION_ERROR", "name must be at most 64 characters")
		return
	}
	existing, err := h.obj.Repo.ListSSHKeys(r.Context(), rec.Bucket)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to add SSH key")
		return
	}
	if len(existing) >= maxSSHKeysPerBucket {
		respondError(w, http.StatusConflict, "CONFLICT", fmt.Sprintf("a bucket accepts at most %d SSH keys: remove one first", maxSSHKeysPerBucket))
		return
	}
	var by *uuid.UUID
	if u := middleware.GetUser(r.Context()); u != nil {
		id := u.ID
		by = &id
	}
	k, err := h.obj.Repo.AddSSHKey(r.Context(), rec.Bucket, name, fp, canonical, by)
	if errors.Is(err, objstore.ErrKeyExists) {
		respondError(w, http.StatusConflict, "CONFLICT", "this key or name is already registered for the bucket")
		return
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to add SSH key")
		return
	}
	h.logger.Info("storage ssh key added", "project", project.Slug, "bucket", rec.Bucket, "fingerprint", fp)
	respondJSON(w, http.StatusCreated, keyView(k))
}

// DeleteSSHKey: DELETE .../storage/{dbID}/ssh-keys/{keyID}  (id, name or fingerprint)
func (h *StorageHandler) DeleteSSHKey(w http.ResponseWriter, r *http.Request) {
	_, rec, project, ok := h.loadObjstore(w, r, authz.ProjectDatabases)
	if !ok {
		return
	}
	ref := chi.URLParam(r, "keyID")
	if err := h.obj.Repo.DeleteSSHKey(r.Context(), rec.Bucket, ref); err != nil {
		if errors.Is(err, objstore.ErrNotFound) {
			respondError(w, http.StatusNotFound, "NOT_FOUND", "SSH key not found")
			return
		}
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to remove SSH key")
		return
	}
	h.logger.Info("storage ssh key removed", "project", project.Slug, "bucket", rec.Bucket, "key", ref)
	respondNoContent(w)
}
