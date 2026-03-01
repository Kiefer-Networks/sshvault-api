package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/stripe/stripe-go/v81"
	"github.com/stripe/stripe-go/v81/checkout/session"
	portalsession "github.com/stripe/stripe-go/v81/billingportal/session"
	"github.com/stripe/stripe-go/v81/webhook"
)

type StripeProvider struct {
	secretKey     string
	webhookSecret string
	priceID       string
	appBaseURL    string
	subRepo       repository.SubscriptionRepository
}

func NewStripeProvider(secretKey, webhookSecret, priceID, appBaseURL string, subRepo repository.SubscriptionRepository) *StripeProvider {
	stripe.Key = secretKey
	if appBaseURL == "" {
		appBaseURL = "https://app.sshvault.app"
	}
	return &StripeProvider{
		secretKey:     secretKey,
		webhookSecret: webhookSecret,
		priceID:       priceID,
		appBaseURL:    appBaseURL,
		subRepo:       subRepo,
	}
}

func (p *StripeProvider) CreateCheckoutSession(ctx context.Context, userID, email string) (string, error) {
	params := &stripe.CheckoutSessionParams{
		Mode: stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(p.priceID),
				Quantity: stripe.Int64(1),
			},
		},
		CustomerEmail: stripe.String(email),
		SuccessURL:    stripe.String(p.appBaseURL + "/billing/success?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:     stripe.String(p.appBaseURL + "/billing/cancel"),
		Metadata: map[string]string{
			"user_id": userID,
		},
	}

	s, err := session.New(params)
	if err != nil {
		return "", fmt.Errorf("creating checkout session: %w", err)
	}

	return s.URL, nil
}

func (p *StripeProvider) CreatePortalSession(ctx context.Context, subscriptionID string) (string, error) {
	sub, err := p.subRepo.GetByProviderSubID(ctx, subscriptionID)
	if err != nil || sub == nil {
		return "", fmt.Errorf("subscription not found")
	}

	if sub.ProviderCustomerID == "" {
		return "", fmt.Errorf("no customer ID associated with subscription")
	}

	params := &stripe.BillingPortalSessionParams{
		Customer:  stripe.String(sub.ProviderCustomerID),
		ReturnURL: stripe.String(p.appBaseURL + "/billing"),
	}

	s, err := portalsession.New(params)
	if err != nil {
		return "", fmt.Errorf("creating portal session: %w", err)
	}

	return s.URL, nil
}

func (p *StripeProvider) HandleWebhook(ctx context.Context, payload, signature string) error {
	event, err := webhook.ConstructEvent([]byte(payload), signature, p.webhookSecret)
	if err != nil {
		return fmt.Errorf("verifying webhook signature: %w", err)
	}

	switch event.Type {
	case "checkout.session.completed":
		return p.handleCheckoutCompleted(ctx, event.Data.Raw)
	case "customer.subscription.updated":
		return p.handleSubscriptionUpdated(ctx, event.Data.Raw)
	case "customer.subscription.deleted":
		return p.handleSubscriptionDeleted(ctx, event.Data.Raw)
	}

	return nil
}

func (p *StripeProvider) handleCheckoutCompleted(ctx context.Context, raw json.RawMessage) error {
	var data struct {
		Subscription string            `json:"subscription"`
		Customer     string            `json:"customer"`
		Metadata     map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("parsing checkout data: %w", err)
	}

	userID := data.Metadata["user_id"]
	if userID == "" {
		return fmt.Errorf("missing user_id in metadata")
	}

	sub := &model.Subscription{
		Provider:           "stripe",
		ProviderSubID:      data.Subscription,
		ProviderCustomerID: data.Customer,
		Status:             model.SubStatusActive,
	}

	if err := parseUUID(userID, &sub.UserID); err != nil {
		return err
	}

	return p.subRepo.Create(ctx, sub)
}

func (p *StripeProvider) handleSubscriptionUpdated(ctx context.Context, raw json.RawMessage) error {
	var data struct {
		ID            string `json:"id"`
		Status        string `json:"status"`
		CurrentPeriod struct {
			Start int64 `json:"start"`
			End   int64 `json:"end"`
		} `json:"current_period"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("parsing subscription data: %w", err)
	}

	sub, err := p.subRepo.GetByProviderSubID(ctx, data.ID)
	if err != nil || sub == nil {
		return fmt.Errorf("subscription not found: %s", data.ID)
	}

	sub.Status = mapStripeStatus(data.Status)
	start := time.Unix(data.CurrentPeriod.Start, 0)
	end := time.Unix(data.CurrentPeriod.End, 0)
	sub.CurrentPeriodStart = &start
	sub.CurrentPeriodEnd = &end

	return p.subRepo.Update(ctx, sub)
}

func (p *StripeProvider) handleSubscriptionDeleted(ctx context.Context, raw json.RawMessage) error {
	var data struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("parsing subscription data: %w", err)
	}

	sub, err := p.subRepo.GetByProviderSubID(ctx, data.ID)
	if err != nil || sub == nil {
		return fmt.Errorf("subscription not found: %s", data.ID)
	}

	sub.Status = model.SubStatusCanceled
	return p.subRepo.Update(ctx, sub)
}

func mapStripeStatus(status string) string {
	switch status {
	case "active":
		return model.SubStatusActive
	case "past_due":
		return model.SubStatusPastDue
	case "canceled":
		return model.SubStatusCanceled
	default:
		return model.SubStatusExpired
	}
}

func parseUUID(s string, target *uuid.UUID) error {
	parsed, err := uuid.Parse(s)
	if err != nil {
		return fmt.Errorf("parsing UUID %q: %w", s, err)
	}
	*target = parsed
	return nil
}
