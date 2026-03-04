package billing

import "context"

// Provider defines the billing provider interface.
type Provider interface {
	CreateCheckoutSession(ctx context.Context, userID, email string) (string, error)
	CreatePortalSession(ctx context.Context, subscriptionID string) (string, error)
	HandleWebhook(ctx context.Context, payload, signature string) error
	CancelSubscription(ctx context.Context, subscriptionID string) error
}

// maskToken truncates a sensitive token for safe logging.
// Shows first 8 characters followed by "..." to prevent full token exposure in logs.
func maskToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:8] + "..."
}
