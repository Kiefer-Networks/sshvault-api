package billing

import (
	"context"
)

// NoopProvider is used for self-hosted instances where billing is disabled.
type NoopProvider struct{}

func NewNoopProvider() *NoopProvider {
	return &NoopProvider{}
}

func (p *NoopProvider) CreateCheckoutSession(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func (p *NoopProvider) CreatePortalSession(_ context.Context, _ string) (string, error) {
	return "", nil
}

func (p *NoopProvider) HandleWebhook(_ context.Context, _, _ string) error {
	return nil
}

func (p *NoopProvider) CancelSubscription(_ context.Context, _ string) error {
	return nil
}
