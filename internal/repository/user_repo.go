package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/model"
)

type UserRepository interface {
	Create(ctx context.Context, user *model.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	Update(ctx context.Context, user *model.User) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
	PurgeDeleted(ctx context.Context, olderThan time.Time) (int64, error)

	// OAuth
	CreateOAuthAccount(ctx context.Context, account *model.OAuthAccount) error
	GetOAuthAccount(ctx context.Context, provider, providerID string) (*model.OAuthAccount, error)
	GetOAuthAccountsByUser(ctx context.Context, userID uuid.UUID) ([]model.OAuthAccount, error)
}
