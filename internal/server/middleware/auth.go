package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/kynto/capsule/backend/internal/domain"
)

type contextKey2 string

const userKey contextKey2 = "user"

func Auth(authSvc domain.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				http.Error(w, `{"error":{"code":"UNAUTHORIZED","message":"missing bearer token"}}`, http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(header, "Bearer ")

			user, err := authSvc.ValidateAccessToken(r.Context(), token)
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

func GetUser(ctx context.Context) *domain.User {
	if u, ok := ctx.Value(userKey).(*domain.User); ok {
		return u
	}
	return nil
}
