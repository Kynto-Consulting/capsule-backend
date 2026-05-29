package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/kynto/capsule/backend/internal/domain"
)

type contextKey2 string

const userKey contextKey2 = "user"

// Auth validates the request bearer token.
// Accepts both JWT access tokens and platform API tokens (cap_ prefix).
func Auth(authSvc domain.AuthService, tokenRepo domain.APITokenRepository, userRepo domain.UserRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"missing bearer token"}}`, http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(header, "Bearer ")

			var user *domain.User
			var err error

			if strings.HasPrefix(token, "cap_") {
				// Platform API token — look up by hash
				user, err = validatePlatformToken(r.Context(), token, tokenRepo, userRepo)
			} else {
				// JWT access token
				user, err = authSvc.ValidateAccessToken(r.Context(), token)
			}

			if err != nil {
				code := "UNAUTHORIZED"
				msg := "invalid token"
				if err == domain.ErrTokenExpired {
					msg = "token expired"
				}
				http.Error(w, `{"error":{"code":"`+code+`","message":"`+msg+`"}}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), userKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func validatePlatformToken(ctx context.Context, plain string, tokenRepo domain.APITokenRepository, userRepo domain.UserRepository) (*domain.User, error) {
	h := sha256.New()
	h.Write([]byte(plain))
	hashed := hex.EncodeToString(h.Sum(nil))

	record, err := tokenRepo.GetByHash(ctx, hashed)
	if err != nil {
		return nil, domain.ErrUnauthorized
	}
	if record.RevokedAt != nil {
		return nil, domain.ErrUnauthorized
	}

	// Touch last used (fire-and-forget)
	go func() {
		_ = tokenRepo.TouchLastUsed(context.Background(), record.ID)
	}()

	user, err := userRepo.GetByID(ctx, record.UserID)
	if err != nil {
		return nil, domain.ErrUnauthorized
	}
	return user, nil
}

func GetUser(ctx context.Context) *domain.User {
	if u, ok := ctx.Value(userKey).(*domain.User); ok {
		return u
	}
	return nil
}
