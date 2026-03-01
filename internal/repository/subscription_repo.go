package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/model"
)

type SubscriptionRepository interface {
	Create(ctx context.Context, sub *model.Subscription) error
	GetByUserID(ctx context.Context, userID uuid.UUID) (*model.Subscription, error)
	GetByProviderSubID(ctx context.Context, providerSubID string) (*model.Subscription, error)
	Update(ctx context.Context, sub *model.Subscription) error
}
