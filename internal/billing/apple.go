package billing

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
)

// AppleProvider handles App Store Server Notifications v2.
type AppleProvider struct {
	sharedSecret string
}

func NewAppleProvider(sharedSecret string) *AppleProvider {
	return &AppleProvider{sharedSecret: sharedSecret}
}

func (p *AppleProvider) CreateCheckoutSession(_ context.Context, _, _ string) (string, error) {
	return "", fmt.Errorf("apple subscriptions are managed via the App Store")
}

func (p *AppleProvider) CreatePortalSession(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("apple subscriptions are managed via the App Store")
}

func (p *AppleProvider) HandleWebhook(_ context.Context, payload, signature string) error {
	// TODO: Implement App Store Server Notifications v2
	// 1. Verify JWS signature
	// 2. Decode signedPayload
	// 3. Update subscription status in DB
	log.Info().Msg("apple webhook received but handler not yet implemented")
	return nil
}

func (p *AppleProvider) CancelSubscription(_ context.Context, _ string) error {
	return fmt.Errorf("apple subscriptions must be cancelled via the App Store")
}
