package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/mail"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/rs/zerolog/log"
	"github.com/stripe/stripe-go/v81"
	portalsession "github.com/stripe/stripe-go/v81/billingportal/session"
	"github.com/stripe/stripe-go/v81/checkout/session"
	stripecustomer "github.com/stripe/stripe-go/v81/customer"
	"github.com/stripe/stripe-go/v81/webhook"
)

type StripeProvider struct {
	secretKey     string
	webhookSecret string
	priceID       string
	apiBaseURL    string
	subRepo       repository.SubscriptionRepository
	mailer        mail.Mailer
}

func NewStripeProvider(secretKey, webhookSecret, priceID, apiBaseURL string, subRepo repository.SubscriptionRepository, mailer mail.Mailer) *StripeProvider {
	stripe.Key = secretKey
	if apiBaseURL == "" {
		apiBaseURL = "https://api.sshvault.app"
	}
	return &StripeProvider{
		secretKey:     secretKey,
		webhookSecret: webhookSecret,
		priceID:       priceID,
		apiBaseURL:    apiBaseURL,
		subRepo:       subRepo,
		mailer:        mailer,
	}
}

func (p *StripeProvider) CreateCheckoutSession(ctx context.Context, userID, email string) (string, error) {
	// Create Stripe Customer first so email is locked (non-editable) in checkout
	custParams := &stripe.CustomerParams{
		Email: stripe.String(email),
	}
	custParams.AddMetadata("shellvault_user_id", userID)
	cust, err := stripecustomer.New(custParams)
	if err != nil {
		return "", fmt.Errorf("creating stripe customer: %w", err)
	}

	params := &stripe.CheckoutSessionParams{
		Mode:     stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		Customer: stripe.String(cust.ID),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{
				Price:    stripe.String(p.priceID),
				Quantity: stripe.Int64(1),
			},
		},
		BillingAddressCollection: stripe.String("auto"),
		CustomerUpdate: &stripe.CheckoutSessionCustomerUpdateParams{
			Name:    stripe.String("auto"),
			Address: stripe.String("auto"),
		},
		TaxIDCollection: &stripe.CheckoutSessionTaxIDCollectionParams{
			Enabled: stripe.Bool(true),
		},
		SuccessURL: stripe.String(p.apiBaseURL + "/v1/billing/success?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String(p.apiBaseURL + "/v1/billing/cancel"),
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
		ReturnURL: stripe.String(p.apiBaseURL + "/v1/billing/success"),
	}

	s, err := portalsession.New(params)
	if err != nil {
		return "", fmt.Errorf("creating portal session: %w", err)
	}

	return s.URL, nil
}

func (p *StripeProvider) HandleWebhook(ctx context.Context, payload, signature string) error {
	event, err := webhook.ConstructEventWithOptions([]byte(payload), signature, p.webhookSecret, webhook.ConstructEventOptions{
		IgnoreAPIVersionMismatch: true,
	})
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
		Subscription    string `json:"subscription"`
		Customer        string `json:"customer"`
		CustomerEmail   string `json:"customer_email"`
		CustomerDetails struct {
			Email string `json:"email"`
		} `json:"customer_details"`
		Metadata map[string]string `json:"metadata"`
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

	if err := p.subRepo.Create(ctx, sub); err != nil {
		return err
	}

	// Send payment confirmation email
	email := data.CustomerDetails.Email
	if email == "" {
		email = data.CustomerEmail
	}
	if email != "" && p.mailer != nil {
		go func() {
			if err := p.mailer.Send(context.Background(), email, "ShellVault – Payment Confirmed", mail.PaymentConfirmationEmailBody(email)); err != nil {
				log.Error().Err(err).Str("email", email).Msg("failed to send payment confirmation email")
			}
		}()
	}

	return nil
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
