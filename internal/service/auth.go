package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/kynto/capsule/backend/internal/domain"
)

const bcryptCost = 12

type authClaims struct {
	UserID string `json:"uid"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Type   string `json:"type"` // "access" | "refresh"
	jwt.RegisteredClaims
}

type AuthService struct {
	users      domain.UserRepository
	secretKey  string
	accessTTL  time.Duration
	refreshTTL time.Duration
	logger     *slog.Logger
}

func NewAuthService(
	users domain.UserRepository,
	secretKey string,
	accessTTL, refreshTTL time.Duration,
	logger *slog.Logger,
) *AuthService {
	return &AuthService{
		users:      users,
		secretKey:  secretKey,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		logger:     logger,
	}
}

func (s *AuthService) Register(ctx context.Context, name, email, password string) (*domain.User, *domain.TokenPair, error) {
	existing, err := s.users.GetByEmail(ctx, email)
	if err != nil && err != domain.ErrNotFound {
		return nil, nil, fmt.Errorf("checking existing user: %w", err)
	}
	if existing != nil {
		return nil, nil, domain.ErrConflict
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, nil, fmt.Errorf("hashing password: %w", err)
	}

	user := &domain.User{
		Name:         name,
		Email:        email,
		PasswordHash: string(hash),
		Role:         "member",
	}

	created, err := s.users.Create(ctx, user)
	if err != nil {
		return nil, nil, fmt.Errorf("creating user: %w", err)
	}

	pair, err := s.issueTokenPair(created)
	if err != nil {
		return nil, nil, err
	}

	return created, pair, nil
}

func (s *AuthService) Login(ctx context.Context, email, password string) (*domain.User, *domain.TokenPair, error) {
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if err == domain.ErrNotFound {
			return nil, nil, domain.ErrUnauthorized
		}
		return nil, nil, fmt.Errorf("fetching user: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, nil, domain.ErrUnauthorized
	}

	pair, err := s.issueTokenPair(user)
	if err != nil {
		return nil, nil, err
	}

	return user, pair, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenPair, error) {
	claims, err := s.parseToken(refreshToken)
	if err != nil {
		return nil, err
	}
	if claims.Type != "refresh" {
		return nil, domain.ErrTokenInvalid
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, domain.ErrTokenInvalid
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("fetching user: %w", err)
	}

	return s.issueTokenPair(user)
}

func (s *AuthService) ValidateAccessToken(ctx context.Context, token string) (*domain.User, error) {
	claims, err := s.parseToken(token)
	if err != nil {
		return nil, err
	}
	if claims.Type != "access" {
		return nil, domain.ErrTokenInvalid
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, domain.ErrTokenInvalid
	}

	return s.users.GetByID(ctx, userID)
}

func (s *AuthService) issueTokenPair(user *domain.User) (*domain.TokenPair, error) {
	now := time.Now()

	accessToken, err := s.signToken(&authClaims{
		UserID: user.ID.String(),
		Email:  user.Email,
		Role:   user.Role,
		Type:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTTL)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("signing access token: %w", err)
	}

	refreshToken, err := s.signToken(&authClaims{
		UserID: user.ID.String(),
		Type:   "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.refreshTTL)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("signing refresh token: %w", err)
	}

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(s.accessTTL.Seconds()),
	}, nil
}

func (s *AuthService) signToken(claims *authClaims) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.secretKey))
}

func (s *AuthService) parseToken(tokenStr string) (*authClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &authClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, domain.ErrTokenInvalid
		}
		return []byte(s.secretKey), nil
	})
	if err != nil {
		if err == jwt.ErrTokenExpired {
			return nil, domain.ErrTokenExpired
		}
		return nil, domain.ErrTokenInvalid
	}

	claims, ok := token.Claims.(*authClaims)
	if !ok || !token.Valid {
		return nil, domain.ErrTokenInvalid
	}
	return claims, nil
}
