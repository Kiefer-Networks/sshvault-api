package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
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
	userRepo   repository.UserRepository
	tokenRepo  repository.TokenRepository
	verifyRepo repository.VerificationRepository
	tx         repository.TransactionRunner
	jwt        *auth.JWTManager
	mailer     MailSender
	bruteForce *middleware.BruteForceGuard
}

type MailSender interface {
	SendVerificationEmail(ctx context.Context, email, token string) error
	SendPasswordResetEmail(ctx context.Context, email, token string) error
}

func NewAuthService(
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	verifyRepo repository.VerificationRepository,
	tx repository.TransactionRunner,
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

var ErrVerificationRequired = errors.New("verification_required")

type RegistrationResponse struct {
	Status string `json:"status"`
}

func registrationAccepted() *RegistrationResponse {
	return &RegistrationResponse{Status: "If registration is available, check your email to verify your account."}
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
	var response *AuthResponse
	err := s.tx.WithTransaction(ctx, func(txCtx context.Context) error {
		current, err := s.userRepo.GetByIDForUpdate(txCtx, user.ID)
		if err != nil {
			return err
		}
		if current == nil || current.Password != user.Password || current.SessionVersion != user.SessionVersion {
			return fmt.Errorf("credentials changed; please sign in again")
		}
		response, err = s.issueTokenPairLocked(txCtx, current, deviceName, nil)
		return err
	})
	return response, err
}

// issueTokenPairLocked requires the user's row lock for the current transaction.
func (s *AuthService) issueTokenPairLocked(ctx context.Context, user *model.User, deviceName string, parent *model.RefreshToken) (*AuthResponse, error) {
	if !user.Verified && !user.VerificationGrandfathered {
		return nil, ErrVerificationRequired
	}
	tokenPair, refreshHash, err := s.jwt.GenerateTokenPair(user.ID, user.SessionVersion)
	if err != nil {
		return nil, fmt.Errorf("generating tokens: %w", err)
	}

	refreshToken := &model.RefreshToken{
		UserID:         user.ID,
		SessionVersion: user.SessionVersion,
		TokenHash:      refreshHash,
		DeviceName:     deviceName,
		ExpiresAt:      time.Now().Add(s.jwt.RefreshTTL()),
	}
	if parent != nil {
		refreshToken.FamilyID = parent.FamilyID
		refreshToken.ParentID = &parent.ID
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

func (s *AuthService) Register(ctx context.Context, req *RegisterRequest) (*RegistrationResponse, error) {
	req.Email = NormalizeEmail(req.Email)

	if err := ValidateEmail(req.Email); err != nil {
		return nil, err
	}

	_, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hashing password: %w", err)
	}

	existing, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("checking existing user: %w", err)
	}
	if existing != nil {
		if !existing.Verified && !existing.VerificationGrandfathered {
			s.sendRegistrationVerification(ctx, existing, req.Email)
		}
		return registrationAccepted(), nil
	}

	// Also check for soft-deleted users occupying the email (unique constraint).
	existingDeleted, err := s.userRepo.GetDeletedByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("checking deleted user: %w", err)
	}
	if existingDeleted != nil {
		return registrationAccepted(), nil
	}

	user := &model.User{
		Email:    req.Email,
		Password: "!unverified:" + uuid.NewString(),
		Verified: false,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			if current, lookupErr := s.userRepo.GetByEmail(ctx, req.Email); lookupErr == nil && current != nil {
				s.sendRegistrationVerification(ctx, current, req.Email)
			}
			return registrationAccepted(), nil
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}

	log.Info().Str("email", maskEmail(req.Email)).Str("user_id", user.ID.String()).Msg("user registered")

	s.sendRegistrationVerification(ctx, user, req.Email)
	return registrationAccepted(), nil
}

func (s *AuthService) sendRegistrationVerification(ctx context.Context, user *model.User, email string) {
	if s.mailer != nil {
		rawToken := uuid.New().String()
		hash := auth.HashToken(rawToken)

		issued := false
		err := s.tx.WithTransaction(ctx, func(txCtx context.Context) error {
			current, err := s.userRepo.GetByIDForUpdate(txCtx, user.ID)
			if err != nil {
				return err
			}
			if current == nil || current.Email != email || current.Verified || current.VerificationGrandfathered || current.SessionVersion != user.SessionVersion {
				return nil
			}
			admitted, err := s.verifyRepo.ReserveMailSend(txCtx, mailRecipientDigest(email), repository.TokenKindEmailVerify)
			if err != nil || !admitted {
				return err
			}
			// Only an admitted delivery supersedes the existing viable link.
			// The version also rejects delayed issuance from older snapshots.
			if err := s.userRepo.RevokeSessions(txCtx, user.ID); err != nil {
				return err
			}
			if err := s.verifyRepo.RevokeAllForUser(txCtx, user.ID, repository.TokenKindEmailVerify); err != nil {
				return err
			}
			token := &repository.VerificationToken{
				UserID:    user.ID,
				TokenHash: hash,
				Kind:      repository.TokenKindEmailVerify,
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}
			if err := s.verifyRepo.Create(txCtx, token); err != nil {
				return err
			}
			issued = true
			return nil
		})
		if err != nil {
			log.Warn().Err(err).Str("email", maskEmail(email)).Msg("failed to store verification token")
		} else if issued {
			if err := s.mailer.SendVerificationEmail(ctx, email, rawToken); err != nil {
				log.Warn().Err(err).Str("email", maskEmail(email)).Msg("failed to send verification email")
			}
		}

	}

}

func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*AuthResponse, error) {
	req.Email = NormalizeEmail(req.Email)

	if err := ValidateEmail(req.Email); err != nil {
		return nil, err
	}

	var attemptID uuid.UUID
	completed := false
	if s.bruteForce != nil {
		var remaining time.Duration
		var err error
		attemptID, remaining, err = s.bruteForce.ReserveAttempt(ctx, req.Email, req.IP)
		if err != nil {
			return nil, fmt.Errorf("reserving login attempt: %w", err)
		}
		if attemptID == uuid.Nil {
			return nil, fmt.Errorf("account temporarily locked, try again in %d minutes", int(remaining.Minutes())+1)
		}
		defer func() {
			if !completed {
				if err := s.bruteForce.CompleteAttempt(ctx, req.Email, attemptID, false); err != nil {
					log.Error().Err(err).Msg("failed to complete login reservation")
				}
			}
		}()
	}
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		return nil, fmt.Errorf("finding user: %w", err)
	}
	if user == nil || (!user.Verified && !user.VerificationGrandfathered) {
		// Perform a dummy password verify to equalize timing with real user lookups
		_, _ = auth.VerifyPassword(req.Password, dummyArgon2Hash)
		// Record failed attempt even for non-existent accounts to prevent enumeration

		log.Warn().Str("email", maskEmail(req.Email)).Msg("login failed: unknown email")
		return nil, fmt.Errorf("invalid credentials")
	}

	valid, err := auth.VerifyPassword(req.Password, user.Password)
	if err != nil || !valid {

		log.Warn().Str("email", maskEmail(req.Email)).Msg("login failed: wrong password")
		return nil, fmt.Errorf("invalid credentials")
	}

	response, err := s.issueTokenPair(ctx, user, req.DeviceName)
	if err != nil {
		return nil, err
	}
	if s.bruteForce != nil {
		if err = s.bruteForce.CompleteAttempt(ctx, req.Email, attemptID, true); err != nil {
			return nil, err
		}
		completed = true
	}
	log.Info().Str("email", maskEmail(req.Email)).Msg("login successful")
	return response, nil
}

func (s *AuthService) Refresh(ctx context.Context, req *RefreshRequest) (*AuthResponse, error) {
	hash := auth.HashToken(req.RefreshToken)
	stored, err := s.tokenRepo.GetByHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("finding refresh token: %w", err)
	}
	invalid := errors.New("invalid or expired refresh token")
	if stored == nil {
		return nil, invalid
	}
	var response *AuthResponse
	replay := false
	err = s.tx.WithTransaction(ctx, func(txCtx context.Context) error {
		// User-first locking matches every credential mutation and serializes refreshes.
		user, err := s.userRepo.GetByIDForUpdate(txCtx, stored.UserID)
		if err != nil {
			return err
		}
		if user == nil {
			return invalid
		}
		current, err := s.tokenRepo.GetByHash(txCtx, hash)
		if err != nil {
			return err
		}
		if current == nil {
			return invalid
		}
		if current.ConsumedAt != nil {
			// Commit revocation before returning the authentication failure. Session
			// versions are user-wide, so revoke all refresh credentials at that boundary.
			if err = s.userRepo.RevokeSessions(txCtx, user.ID); err != nil {
				return err
			}
			if err = s.tokenRepo.RevokeAllForUser(txCtx, user.ID); err != nil {
				return err
			}
			replay = true
			return nil
		}
		if current.SessionVersion != user.SessionVersion {
			return invalid
		}
		consumed, err := s.tokenRepo.ConsumeRefreshToken(txCtx, hash)
		if err != nil {
			return fmt.Errorf("consuming refresh token: %w", err)
		}
		if consumed == nil {
			return invalid
		}
		response, err = s.issueTokenPairLocked(txCtx, user, consumed.DeviceName, consumed)
		return err
	})
	if err != nil {
		return nil, err
	}
	if replay {
		return nil, invalid
	}
	return response, nil
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

// VerifyEmail activates a new account with the password chosen by its mailbox owner.
// Legacy verification only marks the address verified; it never changes existing credentials.
func (s *AuthService) VerifyEmail(ctx context.Context, rawToken, newPassword string) error {
	if len(newPassword) < 8 || len(newPassword) > 256 {
		return fmt.Errorf("password must be between 8 and 256 bytes")
	}
	hash := auth.HashToken(rawToken)
	stored, err := s.verifyRepo.GetByHash(ctx, hash, repository.TokenKindEmailVerify)
	if err != nil {
		return fmt.Errorf("finding verification token: %w", err)
	}
	if stored == nil || !stored.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("invalid or expired verification token")
	}
	passwordHash, err := auth.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hashing activation password: %w", err)
	}
	return s.tx.WithTransaction(ctx, func(txCtx context.Context) error {
		// Lock the user before the token, matching email changes and password resets.
		user, err := s.userRepo.GetByIDForUpdate(txCtx, stored.UserID)
		if err != nil {
			return err
		}
		if user == nil {
			return fmt.Errorf("user not found")
		}
		token, err := s.verifyRepo.ConsumeVerificationToken(txCtx, hash, repository.TokenKindEmailVerify)
		if err != nil {
			return fmt.Errorf("consuming verification token: %w", err)
		}
		if token == nil {
			return fmt.Errorf("invalid or expired verification token")
		}
		if !user.Verified && !user.VerificationGrandfathered {
			err = s.userRepo.ActivateRegistration(txCtx, user.ID, user.Email, passwordHash)
		} else {
			err = s.userRepo.MarkVerified(txCtx, user.ID, user.Email)
		}
		if err != nil {
			return fmt.Errorf("updating user: %w", err)
		}
		return nil
	})
}

// ForgotPassword generates a password reset token and sends it via email.
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	email = NormalizeEmail(email)

	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil || user == nil {
		return nil // Don't reveal if user exists
	}

	rawToken := uuid.New().String()
	issued := false
	if err := s.tx.WithTransaction(ctx, func(txCtx context.Context) error {
		current, err := s.userRepo.GetByIDForUpdate(txCtx, user.ID)
		if err != nil {
			return err
		}
		if current == nil || current.Email != email {
			return nil
		}
		admitted, err := s.verifyRepo.ReserveMailSend(txCtx, mailRecipientDigest(email), repository.TokenKindPasswordReset)
		if err != nil || !admitted {
			return err
		}
		if err = s.verifyRepo.RevokeAllForUser(txCtx, user.ID, repository.TokenKindPasswordReset); err != nil {
			return fmt.Errorf("revoking reset tokens: %w", err)
		}
		token := &repository.VerificationToken{UserID: user.ID, TokenHash: auth.HashToken(rawToken), Kind: repository.TokenKindPasswordReset, ExpiresAt: time.Now().Add(time.Hour)}
		if err = s.verifyRepo.Create(txCtx, token); err != nil {
			return fmt.Errorf("creating reset token: %w", err)
		}
		issued = true
		return nil
	}); err != nil {
		return err
	}
	if !issued {
		return nil
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
	// Reject invalid tokens before the expensive password hash. Consumption below
	// remains authoritative when another request changes the token meanwhile.
	stored, err := s.verifyRepo.GetByHash(ctx, hash, repository.TokenKindPasswordReset)
	if err != nil {
		return fmt.Errorf("finding reset token: %w", err)
	}
	if stored == nil || !stored.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("invalid or expired reset token")
	}
	passwordHash, err := auth.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}
	return s.tx.WithTransaction(ctx, func(txCtx context.Context) error {
		user, err := s.userRepo.GetByIDForUpdate(txCtx, stored.UserID)
		if err != nil {
			return err
		}
		if user == nil {
			return fmt.Errorf("user not found")
		}
		token, err := s.verifyRepo.ConsumeVerificationToken(txCtx, hash, repository.TokenKindPasswordReset)
		if err != nil {
			return fmt.Errorf("consuming reset token: %w", err)
		}
		if token == nil {
			return fmt.Errorf("invalid or expired reset token")
		}
		if err = s.userRepo.UpdatePassword(txCtx, user.ID, user.Password, passwordHash); err != nil {
			return fmt.Errorf("updating password: %w", err)
		}
		if err = s.tokenRepo.RevokeAllForUser(txCtx, user.ID); err != nil {
			return fmt.Errorf("revoking tokens: %w", err)
		}
		return nil
	})
}

// LogoutAll revokes access and refresh tokens under the same user row lock.
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	return s.tx.WithTransaction(ctx, func(txCtx context.Context) error {
		if err := s.userRepo.RevokeSessions(txCtx, userID); err != nil {
			return err
		}
		return s.tokenRepo.RevokeAllForUser(txCtx, userID)
	})
}

func mailRecipientDigest(email string) string {
	return auth.HashToken("mail-recipient:" + NormalizeEmail(email))
}
