package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

type EmailChangeSender interface {
	SendEmailChangeEmail(ctx context.Context, email, token string) error
}

type UserService struct {
	verifyRepo repository.VerificationRepository
	mailer     EmailChangeSender
	userRepo   repository.UserRepository
	tokenRepo  repository.TokenRepository
	tx         repository.TransactionRunner
}

func NewUserService(
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	tx repository.TransactionRunner,
	verifyRepo repository.VerificationRepository,
	mailer EmailChangeSender,
) *UserService {
	return &UserService{
		verifyRepo: verifyRepo,
		mailer:     mailer,
		userRepo:   userRepo,
		tokenRepo:  tokenRepo,
		tx:         tx,
	}
}

type UpdateProfileRequest struct {
	Email           string `json:"email,omitempty"`
	CurrentPassword string `json:"current_password,omitempty"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *UserService) GetProfile(ctx context.Context, userID uuid.UUID) (*model.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("getting user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

func (s *UserService) UpdateProfile(ctx context.Context, userID uuid.UUID, req *UpdateProfileRequest) (*model.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("getting user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	if req.Email != "" {
		req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	}

	if req.Email != "" && req.Email != user.Email {
		if err := ValidateEmail(req.Email); err != nil {
			return nil, fmt.Errorf("invalid email format")
		}
		// Match the byte limit enforced when passwords are set. Reject before
		// any Argon2 work on an oversized, attacker-controlled input.
		if len(req.CurrentPassword) > 256 {
			return nil, fmt.Errorf("invalid current password")
		}
		valid, err := auth.VerifyPasswordContext(ctx, req.CurrentPassword, user.Password)
		if err != nil || !valid {
			return nil, fmt.Errorf("invalid current password")
		}
		existing, err := s.userRepo.GetByEmail(ctx, req.Email)
		if err != nil {
			return nil, fmt.Errorf("checking email: %w", err)
		}
		if existing != nil {
			return nil, fmt.Errorf("email already in use")
		}
		if s.verifyRepo == nil || s.mailer == nil {
			return nil, fmt.Errorf("email change unavailable")
		}
		rawToken := uuid.NewString()
		err = s.tx.WithTransaction(ctx, func(txCtx context.Context) error {
			current, err := s.userRepo.GetByIDForUpdate(txCtx, user.ID)
			if err != nil {
				return err
			}
			if current == nil || current.Password != user.Password || current.SessionVersion != user.SessionVersion || current.Email != user.Email {
				return fmt.Errorf("credentials changed; please sign in again")
			}
			admitted, err := s.verifyRepo.ReserveMailSend(txCtx, mailRecipientDigest(req.Email), repository.TokenKindEmailChange)
			if err != nil {
				return err
			}
			if !admitted {
				return fmt.Errorf("email change temporarily unavailable; retry after one minute")
			}
			if err = s.verifyRepo.RevokeAllForUser(txCtx, user.ID, repository.TokenKindEmailChange); err != nil {
				return err
			}
			if err = s.userRepo.SetPendingEmail(txCtx, user.ID, req.Email); err != nil {
				return err
			}
			return s.verifyRepo.Create(txCtx, &repository.VerificationToken{UserID: user.ID, TokenHash: auth.HashToken(rawToken), Kind: repository.TokenKindEmailChange, ExpiresAt: time.Now().Add(time.Hour)})
		})
		if err != nil {
			return nil, fmt.Errorf("requesting email change: %w", err)
		}
		// pending_email and the verification token are already committed; a mail
		// delivery failure here must not be reported as a failed profile update.
		if err := s.mailer.SendEmailChangeEmail(ctx, req.Email, rawToken); err != nil {
			log.Warn().Err(err).Str("email", maskEmail(req.Email)).Msg("failed to send email change notification")
		}
		user.PendingEmail = req.Email
	}
	return user, nil
}

func (s *UserService) ChangePassword(ctx context.Context, userID uuid.UUID, req *ChangePasswordRequest) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("getting user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	// Match the byte limit enforced when passwords are set. Reject before any
	// Argon2 work on an oversized, attacker-controlled input.
	if len(req.CurrentPassword) > 256 {
		return fmt.Errorf("invalid current password")
	}

	if user.Password != "" {
		valid, err := auth.VerifyPasswordContext(ctx, req.CurrentPassword, user.Password)
		if err != nil || !valid {
			return fmt.Errorf("invalid current password")
		}
	}

	hash, err := auth.HashPasswordContext(ctx, req.NewPassword)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	// Update password and revoke all sessions atomically.
	return s.tx.WithTransaction(ctx, func(txCtx context.Context) error {
		if err := s.userRepo.UpdatePassword(txCtx, user.ID, user.Password, hash); err != nil {
			return fmt.Errorf("updating password: %w", err)
		}
		if err := s.tokenRepo.RevokeAllForUser(txCtx, userID); err != nil {
			return fmt.Errorf("revoking tokens: %w", err)
		}
		return nil
	})
}

func (s *UserService) DeleteAccount(ctx context.Context, userID uuid.UUID) error {
	// Soft delete and revoke all sessions atomically.
	return s.tx.WithTransaction(ctx, func(txCtx context.Context) error {
		if err := s.userRepo.SoftDelete(txCtx, userID); err != nil {
			return fmt.Errorf("deleting account: %w", err)
		}
		if err := s.tokenRepo.RevokeAllForUser(txCtx, userID); err != nil {
			return fmt.Errorf("revoking tokens: %w", err)
		}
		return nil
	})
}

// ConfirmEmailChange locks the account before consuming its purpose-specific token.
// Installing the mailbox and invalidating credentials share the maintenance-locked transaction.
func (s *UserService) ConfirmEmailChange(ctx context.Context, rawToken string) error {
	hash := auth.HashToken(rawToken)
	stored, err := s.verifyRepo.GetByHash(ctx, hash, repository.TokenKindEmailChange)
	if err != nil {
		return err
	}
	if stored == nil || !stored.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("invalid or expired email change token")
	}
	return s.tx.WithTransaction(ctx, func(txCtx context.Context) error {
		user, err := s.userRepo.GetByIDForUpdate(txCtx, stored.UserID)
		if err != nil {
			return err
		}
		if user == nil || user.PendingEmail == "" {
			return fmt.Errorf("invalid or expired email change token")
		}
		consumed, err := s.verifyRepo.ConsumeVerificationToken(txCtx, hash, repository.TokenKindEmailChange)
		if err != nil {
			return err
		}
		if consumed == nil {
			return fmt.Errorf("invalid or expired email change token")
		}
		if err = s.userRepo.ConfirmPendingEmail(txCtx, user.ID, user.PendingEmail); err != nil {
			return err
		}
		if err = s.tokenRepo.RevokeAllForUser(txCtx, user.ID); err != nil {
			return err
		}
		for _, kind := range []string{repository.TokenKindEmailChange, repository.TokenKindEmailVerify, repository.TokenKindPasswordReset} {
			if err = s.verifyRepo.RevokeAllForUser(txCtx, user.ID, kind); err != nil {
				return err
			}
		}
		return nil
	})
}
