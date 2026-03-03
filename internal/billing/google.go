package billing

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
)

// GoogleProvider handles Google Play Billing verification.
type GoogleProvider struct {
	serviceAccountPath string
}

func NewGoogleProvider(serviceAccountPath string) *GoogleProvider {
	return &GoogleProvider{serviceAccountPath: serviceAccountPath}
}

func (p *GoogleProvider) CreateCheckoutSession(_ context.Context, _, _ string) (string, error) {
	return "", fmt.Errorf("google subscriptions are managed via Google Play")
}

func (p *GoogleProvider) CreatePortalSession(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("google subscriptions are managed via Google Play")
}

func (p *GoogleProvider) HandleWebhook(_ context.Context, payload, signature string) error {
	// TODO: Implement Google Play Developer Notifications
	// 1. Verify notification
	// 2. Query Google Play Developer API for subscription status
	// 3. Update subscription status in DB
	log.Info().Msg("google webhook received but handler not yet implemented")
	return nil
}

func (p *GoogleProvider) CancelSubscription(_ context.Context, _ string) error {
	return fmt.Errorf("google subscriptions must be cancelled via Google Play")
}
