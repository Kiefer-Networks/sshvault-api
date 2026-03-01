package billing

import "context"

type Provider interface {
	CreateCheckoutSession(ctx context.Context, userID, email string) (string, error)
	CreatePortalSession(ctx context.Context, subscriptionID string) (string, error)
	HandleWebhook(ctx context.Context, payload, signature string) error
}
