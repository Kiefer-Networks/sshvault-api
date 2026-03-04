package service

import (
	"context"
	"fmt"
	"net/mail"
	"strings"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/billing"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/rs/zerolog/log"
)

type UserService struct {
	userRepo        repository.UserRepository
	tokenRepo       repository.TokenRepository
	subRepo         repository.SubscriptionRepository
	billingProvider billing.Provider
	tx              *repository.Transactor
}

func NewUserService(
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	subRepo repository.SubscriptionRepository,
	billingProvider billing.Provider,
	tx *repository.Transactor,
) *UserService {
	return &UserService{
		userRepo:        userRepo,
		tokenRepo:       tokenRepo,
		subRepo:         subRepo,
		billingProvider: billingProvider,
		tx:              tx,
	}
}

type UpdateProfileRequest struct {
	Email string `json:"email,omitempty"`
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
		if _, err := mail.ParseAddress(req.Email); err != nil {
			return nil, fmt.Errorf("invalid email format")
		}
		existing, err := s.userRepo.GetByEmail(ctx, req.Email)
		if err != nil {
			return nil, fmt.Errorf("checking email: %w", err)
		}
		if existing != nil {
			return nil, fmt.Errorf("email already in use")
		}
		user.Email = req.Email
		user.Verified = false
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("updating user: %w", err)
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

	if user.Password != "" {
		valid, err := auth.VerifyPassword(req.CurrentPassword, user.Password)
		if err != nil || !valid {
			return fmt.Errorf("invalid current password")
		}
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	// Update password and revoke all sessions atomically.
	return s.tx.WithTransaction(ctx, func(txCtx context.Context) error {
		user.Password = hash
		if err := s.userRepo.Update(txCtx, user); err != nil {
			return fmt.Errorf("updating password: %w", err)
		}
		if err := s.tokenRepo.RevokeAllForUser(txCtx, userID); err != nil {
			return fmt.Errorf("revoking tokens: %w", err)
		}
		return nil
	})
}

func (s *UserService) DeleteAccount(ctx context.Context, userID uuid.UUID) error {
	// Cancel active subscription if exists (best-effort).
	if sub, err := s.subRepo.GetByUserID(ctx, userID); err == nil && sub != nil {
		if sub.Status == model.SubStatusActive {
			switch sub.Provider {
			case "stripe":
				if err := s.billingProvider.CancelSubscription(ctx, sub.ProviderSubID); err != nil {
					log.Warn().Err(err).Str("user_id", userID.String()).Msg("failed to cancel Stripe subscription during account deletion")
				}
			case "apple", "google":
				// Store-managed subscriptions: mark as canceled in DB.
				// The actual cancellation is handled by the respective app store.
				sub.Status = model.SubStatusCanceled
				if err := s.subRepo.Update(ctx, sub); err != nil {
					log.Warn().Err(err).Str("user_id", userID.String()).Str("provider", sub.Provider).Msg("failed to cancel subscription during account deletion")
				}
			}
		}
	}

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
