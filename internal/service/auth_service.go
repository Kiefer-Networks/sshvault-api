package service

import (
	"context"
	"fmt"
	"net/mail"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

type AuthService struct {
	userRepo      repository.UserRepository
	tokenRepo     repository.TokenRepository
	verifyRepo    repository.VerificationRepository
	jwt           *auth.JWTManager
	mailer        MailSender
	bruteForce    *middleware.BruteForceGuard
}

type MailSender interface {
	SendVerificationEmail(ctx context.Context, email, token string) error
	SendPasswordResetEmail(ctx context.Context, email, token string) error
}

func NewAuthService(
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	verifyRepo repository.VerificationRepository,
	jwt *auth.JWTManager,
	mailer MailSender,
	bruteForce *middleware.BruteForceGuard,
) *AuthService {
	return &AuthService{
		userRepo:   userRepo,
		tokenRepo:  tokenRepo,
		verifyRepo: verifyRepo,
		jwt:        jwt,
		mailer:     mailer,
		bruteForce: bruteForce,
	}
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	DeviceName string `json:"device_name,omitempty"`
	IP         string `json:"-"` // Set by handler, not from JSON
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type OAuthRequest struct {
	IDToken    string `json:"id_token"`
	DeviceName string `json:"device_name,omitempty"`
}

type AuthResponse struct {
	User         *model.User `json:"user"`
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	ExpiresAt    int64       `json:"expires_at"`
}

// ValidateEmail checks if the email address has a valid format (RFC 5322).
func ValidateEmail(email string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

func (s *AuthService) Register(ctx context.Context, req *RegisterRequest) (*AuthResponse, error) {
	if err := ValidateEmail(req.Email); err != nil {
		return nil, err
	}

	existing, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("checking existing user: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("email already registered")
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	user := &model.User{
		Email:    req.Email,
		Password: hash,
		Verified: false,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("creating user: %w", err)
	}

	log.Info().Str("email", req.Email).Str("user_id", user.ID.String()).Msg("user registered")

	if s.mailer != nil {
		rawToken := uuid.New().String()
		hash := auth.HashToken(rawToken)

		vt := &repository.VerificationToken{
			UserID:    user.ID,
			TokenHash: hash,
			Kind:      repository.TokenKindEmailVerify,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}
		if err := s.verifyRepo.Create(ctx, vt); err != nil {
			log.Warn().Err(err).Str("email", req.Email).Msg("failed to store verification token")
		} else if err := s.mailer.SendVerificationEmail(ctx, user.Email, rawToken); err != nil {
			log.Warn().Err(err).Str("email", req.Email).Msg("failed to send verification email")
		}
	}

	tokenPair, refreshHash, err := s.jwt.GenerateTokenPair(user.ID)
	if err != nil {
		return nil, fmt.Errorf("generating tokens: %w", err)
	}

	refreshToken := &model.RefreshToken{
		UserID:    user.ID,
		TokenHash: refreshHash,
		ExpiresAt: time.Now().Add(s.jwt.RefreshTTL()),
	}
	if err := s.tokenRepo.Create(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("storing refresh token: %w", err)
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    tokenPair.ExpiresAt,
	}, nil
}

func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*AuthResponse, error) {
	if err := ValidateEmail(req.Email); err != nil {
		return nil, err
	}

	// Check IP block
	if s.bruteForce != nil && req.IP != "" {
		if s.bruteForce.IsIPBlocked(ctx, req.IP) {
			log.Warn().Str("ip", req.IP).Msg("login blocked: IP exceeded attempt threshold")
			return nil, fmt.Errorf("too many failed attempts, please try again later")
		}
	}

	// Check account lockout
	if s.bruteForce != nil {
		locked, remaining := s.bruteForce.IsAccountLocked(ctx, req.Email)
		if locked {
			log.Warn().Str("email", req.Email).Dur("remaining", remaining).Msg("login blocked: account locked")
			return nil, fmt.Errorf("account temporarily locked, try again in %d minutes", int(remaining.Minutes())+1)
		}
	}

	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("finding user: %w", err)
	}
	if user == nil {
		// Record failed attempt even for non-existent accounts to prevent enumeration
		if s.bruteForce != nil {
			s.bruteForce.RecordAttempt(ctx, req.Email, req.IP, false)
		}
		log.Warn().Str("email", req.Email).Str("ip", req.IP).Msg("login failed: unknown email")
		return nil, fmt.Errorf("invalid credentials")
	}

	valid, err := auth.VerifyPassword(req.Password, user.Password)
	if err != nil || !valid {
		if s.bruteForce != nil {
			s.bruteForce.RecordAttempt(ctx, req.Email, req.IP, false)
		}
		log.Warn().Str("email", req.Email).Str("ip", req.IP).Msg("login failed: wrong password")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Successful login — record and clear failed attempts
	if s.bruteForce != nil {
		s.bruteForce.RecordAttempt(ctx, req.Email, req.IP, true)
		s.bruteForce.ClearAttempts(ctx, req.Email)
	}
	log.Info().Str("email", req.Email).Str("ip", req.IP).Msg("login successful")

	tokenPair, refreshHash, err := s.jwt.GenerateTokenPair(user.ID)
	if err != nil {
		return nil, fmt.Errorf("generating tokens: %w", err)
	}

	refreshToken := &model.RefreshToken{
		UserID:     user.ID,
		TokenHash:  refreshHash,
		DeviceName: req.DeviceName,
		ExpiresAt:  time.Now().Add(s.jwt.RefreshTTL()),
	}
	if err := s.tokenRepo.Create(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("storing refresh token: %w", err)
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    tokenPair.ExpiresAt,
	}, nil
}

func (s *AuthService) Refresh(ctx context.Context, req *RefreshRequest) (*AuthResponse, error) {
	hash := auth.HashToken(req.RefreshToken)

	stored, err := s.tokenRepo.GetByHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("finding refresh token: %w", err)
	}
	if stored == nil || stored.Revoked || time.Now().After(stored.ExpiresAt) {
		log.Warn().Msg("refresh failed: invalid or expired token")
		return nil, fmt.Errorf("invalid or expired refresh token")
	}

	// Revoke old token (single-use rotation)
	if err := s.tokenRepo.Revoke(ctx, stored.ID); err != nil {
		return nil, fmt.Errorf("revoking old token: %w", err)
	}

	user, err := s.userRepo.GetByID(ctx, stored.UserID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}

	tokenPair, newRefreshHash, err := s.jwt.GenerateTokenPair(user.ID)
	if err != nil {
		return nil, fmt.Errorf("generating tokens: %w", err)
	}

	newRefreshToken := &model.RefreshToken{
		UserID:     user.ID,
		TokenHash:  newRefreshHash,
		DeviceName: stored.DeviceName,
		ExpiresAt:  time.Now().Add(s.jwt.RefreshTTL()),
	}
	if err := s.tokenRepo.Create(ctx, newRefreshToken); err != nil {
		return nil, fmt.Errorf("storing new refresh token: %w", err)
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    tokenPair.ExpiresAt,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	hash := auth.HashToken(refreshToken)
	stored, err := s.tokenRepo.GetByHash(ctx, hash)
	if err != nil {
		return fmt.Errorf("finding refresh token: %w", err)
	}
	if stored == nil {
		return nil // already revoked or doesn't exist
	}
	return s.tokenRepo.Revoke(ctx, stored.ID)
}

func (s *AuthService) OAuthLogin(ctx context.Context, provider auth.OAuthProvider, idToken, deviceName string) (*AuthResponse, error) {
	info, err := provider.VerifyToken(ctx, idToken)
	if err != nil {
		log.Warn().Err(err).Str("provider", "oauth").Msg("OAuth token verification failed")
		return nil, fmt.Errorf("verifying OAuth token: %w", err)
	}

	// Check if OAuth account already linked
	oauthAccount, err := s.userRepo.GetOAuthAccount(ctx, info.Provider, info.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("checking OAuth account: %w", err)
	}

	var user *model.User
	if oauthAccount != nil {
		user, err = s.userRepo.GetByID(ctx, oauthAccount.UserID)
		if err != nil || user == nil {
			return nil, fmt.Errorf("user not found for OAuth account")
		}
	} else {
		if info.Email != "" {
			user, err = s.userRepo.GetByEmail(ctx, info.Email)
			if err != nil {
				return nil, fmt.Errorf("checking email: %w", err)
			}
		}

		if user == nil {
			user = &model.User{
				Email:    info.Email,
				Password: "", // OAuth users don't have a password
				Verified: true,
			}
			if err := s.userRepo.Create(ctx, user); err != nil {
				return nil, fmt.Errorf("creating OAuth user: %w", err)
			}
			log.Info().Str("email", info.Email).Str("provider", info.Provider).Msg("OAuth user registered")
		}

		account := &model.OAuthAccount{
			UserID:     user.ID,
			Provider:   info.Provider,
			ProviderID: info.ProviderID,
			Email:      info.Email,
		}
		if err := s.userRepo.CreateOAuthAccount(ctx, account); err != nil {
			return nil, fmt.Errorf("linking OAuth account: %w", err)
		}
	}

	tokenPair, refreshHash, err := s.jwt.GenerateTokenPair(user.ID)
	if err != nil {
		return nil, fmt.Errorf("generating tokens: %w", err)
	}

	refreshToken := &model.RefreshToken{
		UserID:     user.ID,
		TokenHash:  refreshHash,
		DeviceName: deviceName,
		ExpiresAt:  time.Now().Add(s.jwt.RefreshTTL()),
	}
	if err := s.tokenRepo.Create(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("storing refresh token: %w", err)
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresAt:    tokenPair.ExpiresAt,
	}, nil
}

// VerifyEmail validates an email verification token and marks the user as verified.
func (s *AuthService) VerifyEmail(ctx context.Context, rawToken string) error {
	hash := auth.HashToken(rawToken)
	token, err := s.verifyRepo.GetByHash(ctx, hash, repository.TokenKindEmailVerify)
	if err != nil {
		return fmt.Errorf("looking up token: %w", err)
	}
	if token == nil {
		return fmt.Errorf("invalid or expired verification token")
	}
	if time.Now().After(token.ExpiresAt) {
		return fmt.Errorf("verification token expired")
	}

	user, err := s.userRepo.GetByID(ctx, token.UserID)
	if err != nil || user == nil {
		return fmt.Errorf("user not found")
	}

	user.Verified = true
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("updating user: %w", err)
	}

	if err := s.verifyRepo.MarkUsed(ctx, token.ID); err != nil {
		log.Warn().Err(err).Msg("failed to mark verification token as used")
	}

	log.Info().Str("email", user.Email).Msg("email verified")
	return nil
}

// ForgotPassword generates a password reset token and sends it via email.
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil || user == nil {
		return nil // Don't reveal if user exists
	}

	_ = s.verifyRepo.RevokeAllForUser(ctx, user.ID, repository.TokenKindPasswordReset)

	rawToken := uuid.New().String()
	hash := auth.HashToken(rawToken)

	vt := &repository.VerificationToken{
		UserID:    user.ID,
		TokenHash: hash,
		Kind:      repository.TokenKindPasswordReset,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if err := s.verifyRepo.Create(ctx, vt); err != nil {
		return fmt.Errorf("creating reset token: %w", err)
	}

	if s.mailer != nil {
		if err := s.mailer.SendPasswordResetEmail(ctx, user.Email, rawToken); err != nil {
			log.Warn().Err(err).Str("email", email).Msg("failed to send password reset email")
		}
	}

	log.Info().Str("email", email).Msg("password reset requested")
	return nil
}

// ResetPassword validates a reset token and sets a new password.
func (s *AuthService) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	hash := auth.HashToken(rawToken)
	token, err := s.verifyRepo.GetByHash(ctx, hash, repository.TokenKindPasswordReset)
	if err != nil {
		return fmt.Errorf("looking up token: %w", err)
	}
	if token == nil {
		return fmt.Errorf("invalid or expired reset token")
	}
	if time.Now().After(token.ExpiresAt) {
		return fmt.Errorf("reset token expired")
	}

	user, err := s.userRepo.GetByID(ctx, token.UserID)
	if err != nil || user == nil {
		return fmt.Errorf("user not found")
	}

	passwordHash, err := auth.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	user.Password = passwordHash
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("updating password: %w", err)
	}

	if err := s.verifyRepo.MarkUsed(ctx, token.ID); err != nil {
		log.Warn().Err(err).Msg("failed to mark reset token as used")
	}

	if err := s.tokenRepo.RevokeAllForUser(ctx, user.ID); err != nil {
		log.Warn().Err(err).Msg("failed to revoke tokens after password reset")
	}

	log.Info().Str("user_id", user.ID.String()).Msg("password reset completed")
	return nil
}
