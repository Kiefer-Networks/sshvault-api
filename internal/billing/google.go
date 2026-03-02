package billing

import (
	"context"
	"fmt"
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

func (p *GoogleProvider) HandleWebhook(ctx context.Context, payload, signature string) error {
	// TODO: Implement Google Play Developer Notifications
	// 1. Verify notification
	// 2. Query Google Play Developer API for subscription status
	// 3. Update subscription status in DB
	return fmt.Errorf("google webhook handling not implemented")
}
