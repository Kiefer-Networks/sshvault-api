package service

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

// dummyArgon2Hash is a pre-computed Argon2id hash used for timing equalization
// when a login attempt targets a non-existent user. This ensures the response
// time is indistinguishable from a real user with a wrong password.
const dummyArgon2Hash = "$argon2id$v=19$m=262144,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type AuthService struct {
	userRepo      repository.UserRepository
	tokenRepo     repository.TokenRepository
	verifyRepo    repository.VerificationRepository
	tx            *repository.Transactor
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
	tx *repository.Transactor,
	jwt *auth.JWTManager,
	mailer MailSender,
	bruteForce *middleware.BruteForceGuard,
) *AuthService {
	return &AuthService{
		userRepo:   userRepo,
		tokenRepo:  tokenRepo,
		verifyRepo: verifyRepo,
		tx:         tx,
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

type AuthResponse struct {
	User         *model.User `json:"user"`
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	ExpiresAt    int64       `json:"expires_at"`
}

// issueTokenPair generates an access/refresh token pair, stores the refresh token, and returns an AuthResponse.
func (s *AuthService) issueTokenPair(ctx context.Context, user *model.User, deviceName string) (*AuthResponse, error) {
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

// maskEmail redacts the local part of an email address for log output.
// Example: "user@example.com" -> "us***@example.com"
func maskEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return "***"
	}
	local, domain := parts[0], parts[1]
	if len(local) <= 2 {
		return "***@" + domain
	}
	return local[:2] + "***@" + domain
}

// NormalizeEmail lowercases and trims an email address.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ValidateEmail checks if the email address has a valid format (RFC 5322).
func ValidateEmail(email string) error {
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

func (s *AuthService) Register(ctx context.Context, req *RegisterRequest) (*AuthResponse, error) {
	req.Email = NormalizeEmail(req.Email)

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

	// Also check for soft-deleted users occupying the email (unique constraint).
	existingDeleted, err := s.userRepo.GetDeletedByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("checking deleted user: %w", err)
	}
	if existingDeleted != nil {
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

	log.Info().Str("email", maskEmail(req.Email)).Str("user_id", user.ID.String()).Msg("user registered")

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
			log.Warn().Err(err).Str("email", maskEmail(req.Email)).Msg("failed to store verification token")
		} else if err := s.mailer.SendVerificationEmail(ctx, user.Email, rawToken); err != nil {
			log.Warn().Err(err).Str("email", maskEmail(req.Email)).Msg("failed to send verification email")
		}
	}

	return s.issueTokenPair(ctx, user, "")
}

func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*AuthResponse, error) {
	req.Email = NormalizeEmail(req.Email)

	if err := ValidateEmail(req.Email); err != nil {
		return nil, err
	}

	// Check IP block
	if s.bruteForce != nil && req.IP != "" {
		if s.bruteForce.IsIPBlocked(ctx, req.IP) {
			log.Warn().Msg("login blocked: IP exceeded attempt threshold")
			return nil, fmt.Errorf("too many failed attempts, please try again later")
		}
	}

	// Check account lockout
	if s.bruteForce != nil {
		locked, remaining := s.bruteForce.IsAccountLocked(ctx, req.Email)
		if locked {
			log.Warn().Str("email", maskEmail(req.Email)).Dur("remaining", remaining).Msg("login blocked: account locked")
			return nil, fmt.Errorf("account temporarily locked, try again in %d minutes", int(remaining.Minutes())+1)
		}
	}

	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("finding user: %w", err)
	}
	if user == nil {
		// Perform a dummy password verify to equalize timing with real user lookups
		_, _ = auth.VerifyPassword(req.Password, dummyArgon2Hash)
		// Record failed attempt even for non-existent accounts to prevent enumeration
		if s.bruteForce != nil {
			s.bruteForce.RecordAttempt(ctx, req.Email, req.IP, false)
		}
		log.Warn().Str("email", maskEmail(req.Email)).Msg("login failed: unknown email")
		return nil, fmt.Errorf("invalid credentials")
	}

	valid, err := auth.VerifyPassword(req.Password, user.Password)
	if err != nil || !valid {
		if s.bruteForce != nil {
			s.bruteForce.RecordAttempt(ctx, req.Email, req.IP, false)
		}
		log.Warn().Str("email", maskEmail(req.Email)).Msg("login failed: wrong password")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Successful login — record and clear failed attempts
	if s.bruteForce != nil {
		s.bruteForce.RecordAttempt(ctx, req.Email, req.IP, true)
		s.bruteForce.ClearAttempts(ctx, req.Email)
	}
	log.Info().Str("email", maskEmail(req.Email)).Msg("login successful")

	return s.issueTokenPair(ctx, user, req.DeviceName)
}

func (s *AuthService) Refresh(ctx context.Context, req *RefreshRequest) (*AuthResponse, error) {
	hash := auth.HashToken(req.RefreshToken)

	// Atomically revoke and return the token to prevent race conditions
	// where two concurrent requests could both consume the same token.
	stored, err := s.tokenRepo.ConsumeRefreshToken(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("consuming refresh token: %w", err)
	}
	if stored == nil {
		log.Warn().Msg("refresh failed: invalid, expired, or already consumed token")
		return nil, fmt.Errorf("invalid or expired refresh token")
	}

	user, err := s.userRepo.GetByID(ctx, stored.UserID)
	if err != nil || user == nil {
		return nil, fmt.Errorf("user not found")
	}

	return s.issueTokenPair(ctx, user, stored.DeviceName)
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

// VerifyEmail validates an email verification token and marks the user as verified.
// Uses atomic token consumption to prevent race conditions where two concurrent
// requests with the same token could both succeed.
func (s *AuthService) VerifyEmail(ctx context.Context, rawToken string) error {
	hash := auth.HashToken(rawToken)

	// Atomically mark the token as used and return it, preventing double-use.
	token, err := s.verifyRepo.ConsumeVerificationToken(ctx, hash, repository.TokenKindEmailVerify)
	if err != nil {
		return fmt.Errorf("consuming verification token: %w", err)
	}
	if token == nil {
		return fmt.Errorf("invalid or expired verification token")
	}

	user, err := s.userRepo.GetByID(ctx, token.UserID)
	if err != nil || user == nil {
		return fmt.Errorf("user not found")
	}

	user.Verified = true
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("updating user: %w", err)
	}

	log.Info().Str("email", maskEmail(user.Email)).Msg("email verified")
	return nil
}

// ForgotPassword generates a password reset token and sends it via email.
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	email = NormalizeEmail(email)

	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil || user == nil {
		return nil // Don't reveal if user exists
	}

	if err := s.verifyRepo.RevokeAllForUser(ctx, user.ID, repository.TokenKindPasswordReset); err != nil {
		log.Warn().Err(err).Str("user_id", user.ID.String()).Msg("failed to revoke existing password reset tokens")
	}

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
			log.Warn().Err(err).Str("email", maskEmail(email)).Msg("failed to send password reset email")
		}
	}

	log.Info().Str("email", maskEmail(email)).Msg("password reset requested")
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

	// Update password, mark token used, and revoke all sessions atomically.
	if err := s.tx.WithTransaction(ctx, func(txCtx context.Context) error {
		user.Password = passwordHash
		if err := s.userRepo.Update(txCtx, user); err != nil {
			return fmt.Errorf("updating password: %w", err)
		}
		if err := s.verifyRepo.MarkUsed(txCtx, token.ID); err != nil {
			return fmt.Errorf("marking reset token as used: %w", err)
		}
		if err := s.tokenRepo.RevokeAllForUser(txCtx, user.ID); err != nil {
			return fmt.Errorf("revoking tokens: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	log.Info().Str("user_id", user.ID.String()).Msg("password reset completed")
	return nil
}

// LogoutAll revokes all refresh tokens for the given user.
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	return s.tokenRepo.RevokeAllForUser(ctx, userID)
}
