package service

import (
	"context"
	"fmt"
	"net/mail"
	"strings"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

type UserService struct {
	userRepo  repository.UserRepository
	tokenRepo repository.TokenRepository
	tx        *repository.Transactor
}

func NewUserService(
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	tx *repository.Transactor,
) *UserService {
	return &UserService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		tx:        tx,
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
