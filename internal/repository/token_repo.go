package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/model"
)

type TokenRepository interface {
	Create(ctx context.Context, token *model.RefreshToken) error
	GetByHash(ctx context.Context, tokenHash string) (*model.RefreshToken, error)
	// ConsumeRefreshToken atomically revokes a valid refresh token and returns it.
	// Returns nil if the token does not exist, is already revoked, or is expired.
	ConsumeRefreshToken(ctx context.Context, tokenHash string) (*model.RefreshToken, error)
	Revoke(ctx context.Context, id uuid.UUID) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) (int64, error)
}
