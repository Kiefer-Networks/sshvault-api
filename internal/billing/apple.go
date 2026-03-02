package billing

import (
	"context"
	"fmt"
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

func (p *AppleProvider) HandleWebhook(ctx context.Context, payload, signature string) error {
	// TODO: Implement App Store Server Notifications v2
	// 1. Verify JWS signature
	// 2. Decode signedPayload
	// 3. Update subscription status in DB
	return fmt.Errorf("apple webhook handling not implemented")
}
