package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/internal/server/middleware"
)

type AuthHandler struct {
	svc   domain.AuthService
	cache domain.CacheStore // may be nil
}

func NewAuthHandler(svc domain.AuthService, cache domain.CacheStore) *AuthHandler {
	return &AuthHandler{svc: svc, cache: cache}
}

type registerRequest struct {
	Name           string `json:"name"`
	Email          string `json:"email"`
	Password       string `json:"password"`
	InviteCode     string `json:"invite_code"`
	OnboardingCode string `json:"onboarding_code"`
}

func (req *registerRequest) validate() error {
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Name == "" || req.Email == "" || req.Password == "" {
		return domain.ErrInvalidInput
	}
	if len(req.Password) < 8 {
		return domain.ErrInvalidInput
	}
	return nil
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if err := req.validate(); err != nil {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "name, email, and password (min 8 chars) required")
		return
	}

	user, pair, err := h.svc.Register(r.Context(), req.Name, req.Email, req.Password, req.InviteCode, req.OnboardingCode)
	if err != nil {
		if err == domain.ErrConflict {
			respondError(w, http.StatusConflict, "EMAIL_TAKEN", "email already registered")
			return
		}
		if err == domain.ErrInvalidInviteCode {
			respondError(w, http.StatusForbidden, "INVALID_INVITE_CODE", "invalid registration invite code")
			return
		}
		if err == domain.ErrInvalidOnboardingCode {
			respondError(w, http.StatusForbidden, "INVALID_ONBOARDING_CODE", "invalid global onboarding code")
			return
		}
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, map[string]any{
		"user":   user,
		"tokens": pair,
	})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.Email == "" || req.Password == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "email and password required")
		return
	}

	user, pair, err := h.svc.Login(r.Context(), strings.ToLower(strings.TrimSpace(req.Email)), req.Password)
	if err != nil {
		if err == domain.ErrUnauthorized {
			respondError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid email or password")
			return
		}
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "login failed")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"user":   user,
		"tokens": pair,
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.RefreshToken == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "refresh_token required")
		return
	}

	pair, err := h.svc.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		if err == domain.ErrTokenExpired {
			respondError(w, http.StatusUnauthorized, "TOKEN_EXPIRED", "refresh token expired")
			return
		}
		respondError(w, http.StatusUnauthorized, "TOKEN_INVALID", "invalid refresh token")
		return
	}

	respondJSON(w, http.StatusOK, pair)
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r.Context())
	if user == nil {
		respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return
	}
	respondJSON(w, http.StatusOK, user)
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Logout blacklists the provided refresh token so it cannot be reused.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req logoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.RefreshToken == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "refresh_token required")
		return
	}

	if h.cache != nil {
		hash := sha256.Sum256([]byte(req.RefreshToken))
		key := "blacklist:" + hex.EncodeToString(hash[:])
		const ttl = 7 * 24 * 3600 // 7 days in seconds
		if err := h.cache.Set(r.Context(), key, "1", ttl); err != nil {
			respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "logout failed")
			return
		}
	}

	respondNoContent(w)
}

type onboardingVerifyRequest struct {
	Code string `json:"code"`
}

func (h *AuthHandler) GetOnboardingStatus(w http.ResponseWriter, r *http.Request) {
	saved, secret, qrCodeURI, err := h.svc.GetOnboardingStatus(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"saved":       saved,
		"secret":      secret,
		"qr_code_uri": qrCodeURI,
	})
}

func (h *AuthHandler) VerifyOnboarding(w http.ResponseWriter, r *http.Request) {
	var req onboardingVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}
	if req.Code == "" {
		respondError(w, http.StatusUnprocessableEntity, "VALIDATION_ERROR", "verification code required")
		return
	}

	verified, err := h.svc.VerifyOnboarding(r.Context(), req.Code)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	if !verified {
		respondError(w, http.StatusForbidden, "INVALID_ONBOARDING_CODE", "invalid onboarding verification code")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"success": true,
	})
}
