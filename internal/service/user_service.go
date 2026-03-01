package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

type UserService struct {
	userRepo  repository.UserRepository
	tokenRepo repository.TokenRepository
}

func NewUserService(userRepo repository.UserRepository, tokenRepo repository.TokenRepository) *UserService {
	return &UserService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
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

	if req.Email != "" && req.Email != user.Email {
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

	user.Password = hash
	if err := s.userRepo.Update(ctx, user); err != nil {
		return fmt.Errorf("updating password: %w", err)
	}

	// Revoke all refresh tokens after password change
	if err := s.tokenRepo.RevokeAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("revoking tokens: %w", err)
	}

	return nil
}

func (s *UserService) DeleteAccount(ctx context.Context, userID uuid.UUID) error {
	// Soft delete — data purge after 30 days handled by a background job
	if err := s.userRepo.SoftDelete(ctx, userID); err != nil {
		return fmt.Errorf("deleting account: %w", err)
	}

	// Revoke all tokens
	if err := s.tokenRepo.RevokeAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("revoking tokens: %w", err)
	}

	return nil
}
