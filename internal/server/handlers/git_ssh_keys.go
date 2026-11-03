package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/kynto/capsule/backend/internal/gittokens"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

// SSH keys managed from Capsule and synchronized with Forgejo (SPEC 6.5 point 4):
// gitSshKeysList, gitSshKeyAdd, gitSshKeyDelete.

type gitSSHKeyDTO struct {
	ID            uuid.UUID  `json:"id"`
	Title         string     `json:"title"`
	Fingerprint   string     `json:"fingerprint"`
	CreatedAt     time.Time  `json:"created_at"`
	LastUsedAt    *time.Time `json:"last_used_at"`
	ForgejoSynced bool       `json:"forgejo_synced"`
}

func toKeyDTO(k *gittokens.SSHKey) gitSSHKeyDTO {
	return gitSSHKeyDTO{ID: k.ID, Title: k.Title, Fingerprint: k.Fingerprint, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt, ForgejoSynced: k.ForgejoSynced()}
}

// ListKeys handles GET /user/git-ssh-keys.
func (h *GitTokensHandler) ListKeys(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	keys, err := h.svc.ListKeys(r.Context(), user.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	items := make([]gitSSHKeyDTO, 0, len(keys))
	for _, k := range keys {
		items = append(items, toKeyDTO(k))
	}
	respondJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

// AddKey handles POST /user/git-ssh-keys.
func (h *GitTokensHandler) AddKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	var in struct {
		Title string `json:"title"`
		Key   string `json:"key"`
	}
	if !decodeSmallJSON(w, r, &in) {
		return
	}
	k, err := h.svc.AddKey(r.Context(), user.ID, in.Title, in.Key, middleware.ClientIP(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	respondJSON(w, http.StatusCreated, toKeyDTO(k))
}

// DeleteKey handles DELETE /user/git-ssh-keys/{keyID}.
func (h *GitTokensHandler) DeleteKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_ID", "invalid key id")
		return
	}
	if err := h.svc.DeleteKey(r.Context(), user.ID, id, middleware.ClientIP(r)); err != nil {
		h.fail(w, err)
		return
	}
	respondNoContent(w)
}
