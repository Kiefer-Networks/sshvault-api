package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/billing"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

// TeleportUnlockChecker checks if a user has the teleport addon unlocked.
type TeleportUnlockChecker interface {
	IsTeleportUnlocked(ctx context.Context, userID uuid.UUID) (bool, error)
}

type BillingService struct {
	subRepo           repository.SubscriptionRepository
	provider          billing.Provider
	googleProvider    *billing.GoogleProvider
	appleProvider     *billing.AppleProvider
	enabled           bool
	teleportChecker   TeleportUnlockChecker
}

func NewBillingService(subRepo repository.SubscriptionRepository, provider billing.Provider, enabled bool) *BillingService {
	return &BillingService{
		subRepo:  subRepo,
		provider: provider,
		enabled:  enabled,
	}
}

func (s *BillingService) SetGoogleProvider(gp *billing.GoogleProvider) {
	s.googleProvider = gp
}

func (s *BillingService) GoogleProvider() *billing.GoogleProvider {
	return s.googleProvider
}

func (s *BillingService) SetAppleProvider(ap *billing.AppleProvider) {
	s.appleProvider = ap
}

func (s *BillingService) SetTeleportChecker(tc TeleportUnlockChecker) {
	s.teleportChecker = tc
}

func (s *BillingService) AppleProvider() *billing.AppleProvider {
	return s.appleProvider
}

type BillingStatus struct {
	Active           bool               `json:"active"`
	Provider         string             `json:"provider,omitempty"`
	Status           string             `json:"status,omitempty"`
	TeleportUnlocked bool               `json:"teleport_unlocked"`
	Sub              *model.Subscription `json:"subscription,omitempty"`
}

func (s *BillingService) GetStatus(ctx context.Context, userID uuid.UUID) (*BillingStatus, error) {
	teleportUnlocked := false
	if s.teleportChecker != nil {
		unlocked, err := s.teleportChecker.IsTeleportUnlocked(ctx, userID)
		if err == nil {
			teleportUnlocked = unlocked
		}
	}

	if !s.enabled {
		return &BillingStatus{Active: true, TeleportUnlocked: teleportUnlocked}, nil
	}

	sub, err := s.subRepo.GetByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("getting subscription: %w", err)
	}

	if sub == nil {
		return &BillingStatus{Active: false, TeleportUnlocked: teleportUnlocked}, nil
	}

	return &BillingStatus{
		Active:           sub.Status == model.SubStatusActive,
		Provider:         sub.Provider,
		Status:           sub.Status,
		TeleportUnlocked: teleportUnlocked,
		Sub:              sub,
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
	switch provider {
	case "google":
		if s.googleProvider != nil {
			return s.googleProvider.HandleWebhook(ctx, payload, signature)
		}
		return fmt.Errorf("google provider not configured")
	case "apple":
		if s.appleProvider != nil {
			return s.appleProvider.HandleWebhook(ctx, payload, signature)
		}
		return fmt.Errorf("apple provider not configured")
	default:
		return s.provider.HandleWebhook(ctx, payload, signature)
	}
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

// CreateTeleportCheckoutSession creates a Stripe one-time payment session
// for the Teleport addon.
func (s *BillingService) CreateTeleportCheckoutSession(ctx context.Context, userID uuid.UUID, email string) (string, error) {
	if !s.enabled {
		return "", fmt.Errorf("billing not enabled")
	}

	sp, ok := s.provider.(*billing.StripeProvider)
	if !ok {
		return "", fmt.Errorf("teleport addon checkout requires stripe provider")
	}

	return sp.CreateTeleportCheckoutSession(ctx, userID.String(), email)
}

// SetAddonPurchaseHandler configures the Stripe provider to call the given
// function when a one-time addon purchase completes via webhook.
func (s *BillingService) SetAddonPurchaseHandler(fn func(ctx context.Context, userID, productType string) error) {
	if sp, ok := s.provider.(*billing.StripeProvider); ok {
		sp.SetAddonPurchaseHandler(fn)
	}
}
