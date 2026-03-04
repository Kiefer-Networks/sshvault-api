package billing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2/google"

	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

const androidPublisherScope = "https://www.googleapis.com/auth/androidpublisher"

// GoogleProvider handles Google Play Billing verification via the
// Android Publisher API. Uses direct HTTP calls with service account
// authentication to avoid the large google.golang.org/api dependency.
type GoogleProvider struct {
	packageName string
	httpClient  *http.Client
	subRepo     repository.SubscriptionRepository
}

func NewGoogleProvider(
	serviceAccountPath string,
	packageName string,
	subRepo repository.SubscriptionRepository,
) (*GoogleProvider, error) {
	data, err := os.ReadFile(serviceAccountPath)
	if err != nil {
		return nil, fmt.Errorf("reading service account key: %w", err)
	}

	conf, err := google.JWTConfigFromJSON(data, androidPublisherScope)
	if err != nil {
		return nil, fmt.Errorf("parsing service account key: %w", err)
	}

	return &GoogleProvider{
		packageName: packageName,
		httpClient:  conf.Client(context.Background()),
		subRepo:     subRepo,
	}, nil
}

func (p *GoogleProvider) CreateCheckoutSession(_ context.Context, _, _ string) (string, error) {
	return "", fmt.Errorf("google subscriptions are managed via Google Play")
}

func (p *GoogleProvider) CreatePortalSession(_ context.Context, _ string) (string, error) {
	return "", fmt.Errorf("google subscriptions are managed via Google Play")
}

func (p *GoogleProvider) CancelSubscription(_ context.Context, _ string) error {
	return fmt.Errorf("google subscriptions must be cancelled via Google Play")
}

// VerifyPurchase verifies a purchase token against the Google Play Developer API
// and returns the parsed subscription purchase response.
func (p *GoogleProvider) VerifyPurchase(ctx context.Context, purchaseToken string) (*GoogleSubscription, error) {
	url := fmt.Sprintf(
		"https://androidpublisher.googleapis.com/androidpublisher/v3/applications/%s/purchases/subscriptionsv2/tokens/%s",
		p.packageName, purchaseToken,
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling Google API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google API error (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var sub GoogleSubscription
	if err := json.Unmarshal(body, &sub); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &sub, nil
}

// HandleWebhook processes Google Play Real-Time Developer Notifications (RTDN)
// delivered via Cloud Pub/Sub push subscriptions.
func (p *GoogleProvider) HandleWebhook(ctx context.Context, payload, _ string) error {
	var msg pubSubMessage
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		return fmt.Errorf("parsing pub/sub message: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(msg.Message.Data)
	if err != nil {
		return fmt.Errorf("decoding notification data: %w", err)
	}

	var notification developerNotification
	if err := json.Unmarshal(decoded, &notification); err != nil {
		return fmt.Errorf("parsing notification: %w", err)
	}

	// Only handle subscription notifications
	if notification.SubscriptionNotification == nil {
		log.Info().Msg("ignoring non-subscription Google notification")
		return nil
	}

	subNotif := notification.SubscriptionNotification
	log.Info().
		Int("type", subNotif.NotificationType).
		Str("purchase_token", subNotif.PurchaseToken).
		Str("subscription_id", subNotif.SubscriptionID).
		Msg("processing Google subscription notification")

	// Verify the current state via API
	googleSub, err := p.VerifyPurchase(ctx, subNotif.PurchaseToken)
	if err != nil {
		return fmt.Errorf("verifying purchase for webhook: %w", err)
	}

	// Look up subscription in our DB by purchase token
	sub, err := p.subRepo.GetByProviderSubID(ctx, subNotif.PurchaseToken)
	if err != nil || sub == nil {
		log.Warn().
			Str("purchase_token", subNotif.PurchaseToken).
			Msg("Google webhook for unknown subscription, skipping")
		return nil
	}

	// Update subscription status based on Google's response
	newStatus := mapGoogleSubscriptionState(googleSub.SubscriptionState)
	if newStatus != sub.Status {
		sub.Status = newStatus
		if googleSub.ExpiryTime != "" {
			if t, err := time.Parse(time.RFC3339, googleSub.ExpiryTime); err == nil {
				sub.CurrentPeriodEnd = &t
			}
		}
		if googleSub.StartTime != "" {
			if t, err := time.Parse(time.RFC3339, googleSub.StartTime); err == nil {
				sub.CurrentPeriodStart = &t
			}
		}
		if err := p.subRepo.Update(ctx, sub); err != nil {
			return fmt.Errorf("updating subscription: %w", err)
		}
		log.Info().
			Str("sub_id", sub.ID.String()).
			Str("old_status", sub.Status).
			Str("new_status", newStatus).
			Msg("updated Google subscription status via webhook")
	}

	return nil
}

// VerifyAndUpsert verifies a purchase token and creates or updates the
// subscription in the database for the given user.
func (p *GoogleProvider) VerifyAndUpsert(ctx context.Context, userID uuid.UUID, purchaseToken string) (*model.Subscription, error) {
	googleSub, err := p.VerifyPurchase(ctx, purchaseToken)
	if err != nil {
		return nil, fmt.Errorf("verifying purchase: %w", err)
	}

	status := mapGoogleSubscriptionState(googleSub.SubscriptionState)

	// Check if subscription already exists for this user
	existing, _ := p.subRepo.GetByUserID(ctx, userID)

	if existing != nil {
		existing.Provider = "google"
		existing.ProviderSubID = purchaseToken
		existing.Status = status
		if googleSub.StartTime != "" {
			if t, err := time.Parse(time.RFC3339, googleSub.StartTime); err == nil {
				existing.CurrentPeriodStart = &t
			}
		}
		if googleSub.ExpiryTime != "" {
			if t, err := time.Parse(time.RFC3339, googleSub.ExpiryTime); err == nil {
				existing.CurrentPeriodEnd = &t
			}
		}
		if err := p.subRepo.Update(ctx, existing); err != nil {
			return nil, fmt.Errorf("updating subscription: %w", err)
		}
		return existing, nil
	}

	// Create new subscription
	sub := &model.Subscription{
		ID:            uuid.New(),
		UserID:        userID,
		Provider:      "google",
		ProviderSubID: purchaseToken,
		Status:        status,
	}
	if googleSub.StartTime != "" {
		if t, err := time.Parse(time.RFC3339, googleSub.StartTime); err == nil {
			sub.CurrentPeriodStart = &t
		}
	}
	if googleSub.ExpiryTime != "" {
		if t, err := time.Parse(time.RFC3339, googleSub.ExpiryTime); err == nil {
			sub.CurrentPeriodEnd = &t
		}
	}
	if err := p.subRepo.Create(ctx, sub); err != nil {
		return nil, fmt.Errorf("creating subscription: %w", err)
	}

	return sub, nil
}

// ============================================================
// GOOGLE PLAY API TYPES
// ============================================================

// GoogleSubscription represents the response from the subscriptions.v2
// purchases API endpoint.
type GoogleSubscription struct {
	Kind              string `json:"kind"`
	SubscriptionState string `json:"subscriptionState"`
	StartTime         string `json:"startTime"`
	ExpiryTime        string `json:"expiryTime"`
}

// Pub/Sub push message envelope.
type pubSubMessage struct {
	Message struct {
		Data        string `json:"data"`
		MessageID   string `json:"messageId"`
		PublishTime string `json:"publishTime"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

// Google Play Developer Notification.
type developerNotification struct {
	Version                  string                    `json:"version"`
	PackageName              string                    `json:"packageName"`
	EventTimeMillis          string                    `json:"eventTimeMillis"`
	SubscriptionNotification *subscriptionNotification `json:"subscriptionNotification"`
}

type subscriptionNotification struct {
	Version          string `json:"version"`
	NotificationType int    `json:"notificationType"`
	PurchaseToken    string `json:"purchaseToken"`
	SubscriptionID   string `json:"subscriptionId"`
}

// Google Play subscription states.
const (
	googleStateActive      = "SUBSCRIPTION_STATE_ACTIVE"
	googleStateCanceled    = "SUBSCRIPTION_STATE_CANCELED"
	googleStateGracePeriod = "SUBSCRIPTION_STATE_IN_GRACE_PERIOD"
	googleStateOnHold      = "SUBSCRIPTION_STATE_ON_HOLD"
	googleStatePaused      = "SUBSCRIPTION_STATE_PAUSED"
	googleStateExpired     = "SUBSCRIPTION_STATE_EXPIRED"
)

func mapGoogleSubscriptionState(state string) string {
	switch state {
	case googleStateActive, googleStateGracePeriod:
		return model.SubStatusActive
	case googleStateCanceled, googleStatePaused:
		return model.SubStatusCanceled
	case googleStateOnHold:
		return model.SubStatusPastDue
	case googleStateExpired:
		return model.SubStatusExpired
	default:
		return model.SubStatusCanceled
	}
}
