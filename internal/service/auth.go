package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/kynto/capsule/backend/internal/domain"
	"github.com/kynto/capsule/backend/pkg/totp"
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
	settings   domain.SettingsRepository
	secretKey  string
	accessTTL  time.Duration
	refreshTTL time.Duration
	logger     *slog.Logger
}

func NewAuthService(
	users domain.UserRepository,
	settings domain.SettingsRepository,
	secretKey string,
	accessTTL, refreshTTL time.Duration,
	logger *slog.Logger,
) *AuthService {
	return &AuthService{
		users:      users,
		settings:   settings,
		secretKey:  secretKey,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		logger:     logger,
	}
}

func (s *AuthService) Register(ctx context.Context, name, email, password, inviteCode, onboardingCode string) (*domain.User, *domain.TokenPair, error) {
	// 1. Invite code verification
	envInvite := os.Getenv("REGISTRATION_INVITE_CODE")
	if envInvite != "" && inviteCode != envInvite {
		return nil, nil, domain.ErrInvalidInviteCode
	}

	// 2. Global Onboarding 2FA validation
	savedStr, err := s.settings.Get(ctx, "global_2fa_saved")
	if err != nil {
		return nil, nil, fmt.Errorf("getting global 2fa saved state: %w", err)
	}
	secret, err := s.settings.Get(ctx, "global_2fa_secret")
	if err != nil {
		return nil, nil, fmt.Errorf("getting global 2fa secret: %w", err)
	}

	if secret == "" {
		return nil, nil, fmt.Errorf("global 2fa secret is not set yet; please retrieve onboarding status first")
	}

	if !totp.VerifyCode(secret, onboardingCode) {
		return nil, nil, domain.ErrInvalidOnboardingCode
	}

	// If successfully validated and onboarding was false, save it as completed
	if savedStr != "true" {
		if err := s.settings.Set(ctx, "global_2fa_saved", "true"); err != nil {
			return nil, nil, fmt.Errorf("saving global 2fa status: %w", err)
		}
	}

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

	// Automatically make the first registered user an 'admin', other users are 'member'
	// This helps with multi-user setups!
	var role = "member"
	if savedStr != "true" {
		role = "admin"
	}

	user := &domain.User{
		Name:         name,
		Email:        email,
		PasswordHash: string(hash),
		Role:         role,
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

	if user.Role == "suspended" {
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

func (s *AuthService) GetOnboardingStatus(ctx context.Context) (saved bool, secret string, qrCodeURI string, err error) {
	savedStr, err := s.settings.Get(ctx, "global_2fa_saved")
	if err != nil {
		return false, "", "", fmt.Errorf("getting global 2fa saved state: %w", err)
	}

	if savedStr == "true" {
		return true, "", "", nil
	}

	// Not saved yet, fetch or generate secret
	secret, err = s.settings.Get(ctx, "global_2fa_secret")
	if err != nil {
		return false, "", "", fmt.Errorf("getting global 2fa secret: %w", err)
	}

	if secret == "" {
		// Generate a new secure secret!
		secret, err = totp.GenerateSecret()
		if err != nil {
			return false, "", "", fmt.Errorf("generating secure secret: %w", err)
		}
		if err := s.settings.Set(ctx, "global_2fa_secret", secret); err != nil {
			return false, "", "", fmt.Errorf("saving new global 2fa secret: %w", err)
		}
		if err := s.settings.Set(ctx, "global_2fa_saved", "false"); err != nil {
			return false, "", "", fmt.Errorf("saving global 2fa default saved state: %w", err)
		}
	}

	qrCodeURI = totp.ProvisioningURI(secret, "AdminOnboarding", "Capsule")
	return false, secret, qrCodeURI, nil
}

func (s *AuthService) VerifyOnboarding(ctx context.Context, code string) (bool, error) {
	savedStr, err := s.settings.Get(ctx, "global_2fa_saved")
	if err != nil {
		return false, fmt.Errorf("getting global 2fa saved state: %w", err)
	}

	if savedStr == "true" {
		return true, nil // Already saved!
	}

	secret, err := s.settings.Get(ctx, "global_2fa_secret")
	if err != nil {
		return false, fmt.Errorf("getting global 2fa secret: %w", err)
	}

	if secret == "" {
		return false, fmt.Errorf("no onboarding 2fa secret has been generated yet; get onboarding status first")
	}

	if !totp.VerifyCode(secret, code) {
		return false, nil // Invalid code
	}

	// Validated successfully! Save it.
	if err := s.settings.Set(ctx, "global_2fa_saved", "true"); err != nil {
		return false, fmt.Errorf("saving global 2fa status: %w", err)
	}

	return true, nil
}
