package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/billing"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

type BillingService struct {
	subRepo  repository.SubscriptionRepository
	provider billing.Provider
	enabled  bool
}

func NewBillingService(subRepo repository.SubscriptionRepository, provider billing.Provider, enabled bool) *BillingService {
	return &BillingService{
		subRepo:  subRepo,
		provider: provider,
		enabled:  enabled,
	}
}

type BillingStatus struct {
	Active   bool               `json:"active"`
	Provider string             `json:"provider,omitempty"`
	Status   string             `json:"status,omitempty"`
	Sub      *model.Subscription `json:"subscription,omitempty"`
}

func (s *BillingService) GetStatus(ctx context.Context, userID uuid.UUID) (*BillingStatus, error) {
	if !s.enabled {
		return &BillingStatus{Active: true}, nil
	}

	sub, err := s.subRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("getting subscription: %w", err)
	}

	if sub == nil {
		return &BillingStatus{Active: false}, nil
	}

	return &BillingStatus{
		Active:   sub.Status == model.SubStatusActive,
		Provider: sub.Provider,
		Status:   sub.Status,
		Sub:      sub,
	}, nil
}

func (s *BillingService) CreateCheckoutSession(ctx context.Context, userID uuid.UUID, email string) (string, error) {
	if !s.enabled {
		return "", fmt.Errorf("billing not enabled")
	}
	return s.provider.CreateCheckoutSession(ctx, userID.String(), email)
}

func (s *BillingService) CreatePortalSession(ctx context.Context, userID uuid.UUID) (string, error) {
	if !s.enabled {
		return "", fmt.Errorf("billing not enabled")
	}

	sub, err := s.subRepo.GetByUserID(ctx, userID)
	if err != nil || sub == nil {
		return "", fmt.Errorf("no active subscription")
	}

	return s.provider.CreatePortalSession(ctx, sub.ProviderSubID)
}

func (s *BillingService) HandleWebhook(ctx context.Context, provider, payload string, signature string) error {
	return s.provider.HandleWebhook(ctx, payload, signature)
}

func (s *BillingService) IsActive(ctx context.Context, userID uuid.UUID) bool {
	if !s.enabled {
		return true // Self-hosted: always active
	}

	sub, err := s.subRepo.GetByUserID(ctx, userID)
	if err != nil || sub == nil {
		return false
	}
	return sub.Status == model.SubStatusActive
}
