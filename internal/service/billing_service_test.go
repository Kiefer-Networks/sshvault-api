package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/model"
)

// --- Mock Subscription Repository ---

type mockSubRepo struct {
	subs          map[uuid.UUID]*model.Subscription
	providerIndex map[string]*model.Subscription
	getErr        error
}

func newMockSubRepo() *mockSubRepo {
	return &mockSubRepo{
		subs:          make(map[uuid.UUID]*model.Subscription),
		providerIndex: make(map[string]*model.Subscription),
	}
}

func (m *mockSubRepo) Create(_ context.Context, sub *model.Subscription) error {
	sub.ID = uuid.New()
	sub.CreatedAt = time.Now()
	sub.UpdatedAt = time.Now()
	m.subs[sub.UserID] = sub
	m.providerIndex[sub.ProviderSubID] = sub
	return nil
}

func (m *mockSubRepo) GetByUserID(_ context.Context, userID uuid.UUID) (*model.Subscription, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.subs[userID], nil
}

func (m *mockSubRepo) GetByProviderSubID(_ context.Context, providerSubID string) (*model.Subscription, error) {
	return m.providerIndex[providerSubID], nil
}

func (m *mockSubRepo) Update(_ context.Context, sub *model.Subscription) error {
	sub.UpdatedAt = time.Now()
	m.subs[sub.UserID] = sub
	return nil
}

// --- Mock Billing Provider ---

type mockBillingProvider struct {
	checkoutURL string
	checkoutErr error
	portalURL   string
	portalErr   error
	webhookErr  error
}

func (m *mockBillingProvider) CreateCheckoutSession(_ context.Context, _, _ string) (string, error) {
	return m.checkoutURL, m.checkoutErr
}

func (m *mockBillingProvider) CreatePortalSession(_ context.Context, _ string) (string, error) {
	return m.portalURL, m.portalErr
}

func (m *mockBillingProvider) HandleWebhook(_ context.Context, _, _ string) error {
	return m.webhookErr
}

func (m *mockBillingProvider) CancelSubscription(_ context.Context, _ string) error {
	return nil
}

// --- Helpers ---

func seedSubscription(repo *mockSubRepo, userID uuid.UUID, status, provider, subID string) *model.Subscription {
	sub := &model.Subscription{
		ID:            uuid.New(),
		UserID:        userID,
		Provider:      provider,
		ProviderSubID: subID,
		Status:        status,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	repo.subs[userID] = sub
	repo.providerIndex[subID] = sub
	return sub
}

// --- GetStatus Tests ---

func TestGetStatusBillingDisabled(t *testing.T) {
	svc := NewBillingService(newMockSubRepo(), &mockBillingProvider{}, false)

	status, err := svc.GetStatus(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if !status.Active {
		t.Error("expected Active=true when billing is disabled")
	}
	if status.Provider != "" {
		t.Errorf("Provider = %q, want empty when billing disabled", status.Provider)
	}
}

func TestGetStatusNoSubscription(t *testing.T) {
	svc := NewBillingService(newMockSubRepo(), &mockBillingProvider{}, true)

	status, err := svc.GetStatus(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.Active {
		t.Error("expected Active=false when no subscription exists")
	}
}

func TestGetStatusActiveSubscription(t *testing.T) {
	repo := newMockSubRepo()
	svc := NewBillingService(repo, &mockBillingProvider{}, true)

	userID := uuid.New()
	seedSubscription(repo, userID, model.SubStatusActive, "stripe", "sub_123")

	status, err := svc.GetStatus(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if !status.Active {
		t.Error("expected Active=true for active subscription")
	}
	if status.Provider != "stripe" {
		t.Errorf("Provider = %q, want %q", status.Provider, "stripe")
	}
	if status.Status != model.SubStatusActive {
		t.Errorf("Status = %q, want %q", status.Status, model.SubStatusActive)
	}
	if status.Sub == nil {
		t.Error("expected subscription object in response")
	}
}

func TestGetStatusCanceledSubscription(t *testing.T) {
	repo := newMockSubRepo()
	svc := NewBillingService(repo, &mockBillingProvider{}, true)

	userID := uuid.New()
	seedSubscription(repo, userID, model.SubStatusCanceled, "stripe", "sub_456")

	status, err := svc.GetStatus(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.Active {
		t.Error("expected Active=false for canceled subscription")
	}
	if status.Status != model.SubStatusCanceled {
		t.Errorf("Status = %q, want %q", status.Status, model.SubStatusCanceled)
	}
}

func TestGetStatusExpiredSubscription(t *testing.T) {
	repo := newMockSubRepo()
	svc := NewBillingService(repo, &mockBillingProvider{}, true)

	userID := uuid.New()
	seedSubscription(repo, userID, model.SubStatusExpired, "apple", "sub_789")

	status, err := svc.GetStatus(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.Active {
		t.Error("expected Active=false for expired subscription")
	}
}

func TestGetStatusPastDueSubscription(t *testing.T) {
	repo := newMockSubRepo()
	svc := NewBillingService(repo, &mockBillingProvider{}, true)

	userID := uuid.New()
	seedSubscription(repo, userID, model.SubStatusPastDue, "google", "sub_101")

	status, err := svc.GetStatus(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.Active {
		t.Error("expected Active=false for past_due subscription")
	}
}

func TestGetStatusRepoError(t *testing.T) {
	repo := newMockSubRepo()
	repo.getErr = fmt.Errorf("database unreachable")
	svc := NewBillingService(repo, &mockBillingProvider{}, true)

	_, err := svc.GetStatus(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
	if !strings.Contains(err.Error(), "getting subscription") {
		t.Errorf("error = %q, want 'getting subscription'", err.Error())
	}
}

// --- CreateCheckoutSession Tests ---

func TestCreateCheckoutSessionSuccess(t *testing.T) {
	provider := &mockBillingProvider{checkoutURL: "https://checkout.stripe.com/session_abc"}
	svc := NewBillingService(newMockSubRepo(), provider, true)

	url, err := svc.CreateCheckoutSession(context.Background(), uuid.New(), "user@example.com")
	if err != nil {
		t.Fatalf("CreateCheckoutSession: %v", err)
	}
	if url != "https://checkout.stripe.com/session_abc" {
		t.Errorf("URL = %q, want checkout URL", url)
	}
}

func TestCreateCheckoutSessionBillingDisabled(t *testing.T) {
	svc := NewBillingService(newMockSubRepo(), &mockBillingProvider{}, false)

	_, err := svc.CreateCheckoutSession(context.Background(), uuid.New(), "user@example.com")
	if err == nil {
		t.Fatal("expected error when billing is disabled")
	}
	if !strings.Contains(err.Error(), "billing not enabled") {
		t.Errorf("error = %q, want 'billing not enabled'", err.Error())
	}
}

func TestCreateCheckoutSessionProviderError(t *testing.T) {
	provider := &mockBillingProvider{checkoutErr: fmt.Errorf("stripe API error")}
	svc := NewBillingService(newMockSubRepo(), provider, true)

	_, err := svc.CreateCheckoutSession(context.Background(), uuid.New(), "user@example.com")
	if err == nil {
		t.Fatal("expected error when provider fails")
	}
	if !strings.Contains(err.Error(), "stripe API error") {
		t.Errorf("error = %q, want 'stripe API error'", err.Error())
	}
}

// --- CreatePortalSession Tests ---

func TestCreatePortalSessionSuccess(t *testing.T) {
	repo := newMockSubRepo()
	provider := &mockBillingProvider{portalURL: "https://billing.stripe.com/portal_abc"}
	svc := NewBillingService(repo, provider, true)

	userID := uuid.New()
	seedSubscription(repo, userID, model.SubStatusActive, "stripe", "sub_portal_123")

	url, err := svc.CreatePortalSession(context.Background(), userID)
	if err != nil {
		t.Fatalf("CreatePortalSession: %v", err)
	}
	if url != "https://billing.stripe.com/portal_abc" {
		t.Errorf("URL = %q, want portal URL", url)
	}
}

func TestCreatePortalSessionBillingDisabled(t *testing.T) {
	svc := NewBillingService(newMockSubRepo(), &mockBillingProvider{}, false)

	_, err := svc.CreatePortalSession(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error when billing is disabled")
	}
	if !strings.Contains(err.Error(), "billing not enabled") {
		t.Errorf("error = %q, want 'billing not enabled'", err.Error())
	}
}

func TestCreatePortalSessionNoSubscription(t *testing.T) {
	svc := NewBillingService(newMockSubRepo(), &mockBillingProvider{}, true)

	_, err := svc.CreatePortalSession(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error when no subscription exists")
	}
	if !strings.Contains(err.Error(), "no active subscription") {
		t.Errorf("error = %q, want 'no active subscription'", err.Error())
	}
}

func TestCreatePortalSessionRepoError(t *testing.T) {
	repo := newMockSubRepo()
	repo.getErr = fmt.Errorf("db error")
	svc := NewBillingService(repo, &mockBillingProvider{}, true)

	_, err := svc.CreatePortalSession(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error when repo fails")
	}
	if !strings.Contains(err.Error(), "no active subscription") {
		t.Errorf("error = %q, want 'no active subscription'", err.Error())
	}
}

func TestCreatePortalSessionProviderError(t *testing.T) {
	repo := newMockSubRepo()
	provider := &mockBillingProvider{portalErr: fmt.Errorf("provider unavailable")}
	svc := NewBillingService(repo, provider, true)

	userID := uuid.New()
	seedSubscription(repo, userID, model.SubStatusActive, "stripe", "sub_portal_err")

	_, err := svc.CreatePortalSession(context.Background(), userID)
	if err == nil {
		t.Fatal("expected error when provider fails")
	}
	if !strings.Contains(err.Error(), "provider unavailable") {
		t.Errorf("error = %q, want 'provider unavailable'", err.Error())
	}
}

// --- HandleWebhook Tests ---

func TestHandleWebhookSuccess(t *testing.T) {
	provider := &mockBillingProvider{}
	svc := NewBillingService(newMockSubRepo(), provider, true)

	err := svc.HandleWebhook(context.Background(), "stripe", `{"type":"checkout.session.completed"}`, "sig_abc")
	if err != nil {
		t.Fatalf("HandleWebhook: %v", err)
	}
}

func TestHandleWebhookProviderError(t *testing.T) {
	provider := &mockBillingProvider{webhookErr: fmt.Errorf("invalid signature")}
	svc := NewBillingService(newMockSubRepo(), provider, true)

	err := svc.HandleWebhook(context.Background(), "stripe", `{}`, "bad_sig")
	if err == nil {
		t.Fatal("expected error when webhook handling fails")
	}
	if !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("error = %q, want 'invalid signature'", err.Error())
	}
}

// --- IsActive Tests ---

func TestIsActiveBillingDisabled(t *testing.T) {
	svc := NewBillingService(newMockSubRepo(), &mockBillingProvider{}, false)

	if !svc.IsActive(context.Background(), uuid.New()) {
		t.Error("expected IsActive=true when billing disabled (self-hosted)")
	}
}

func TestIsActiveNoSubscription(t *testing.T) {
	svc := NewBillingService(newMockSubRepo(), &mockBillingProvider{}, true)

	if svc.IsActive(context.Background(), uuid.New()) {
		t.Error("expected IsActive=false when no subscription exists")
	}
}

func TestIsActiveActiveSubscription(t *testing.T) {
	repo := newMockSubRepo()
	svc := NewBillingService(repo, &mockBillingProvider{}, true)

	userID := uuid.New()
	seedSubscription(repo, userID, model.SubStatusActive, "stripe", "sub_active")

	if !svc.IsActive(context.Background(), userID) {
		t.Error("expected IsActive=true for active subscription")
	}
}

func TestIsActiveCanceledSubscription(t *testing.T) {
	repo := newMockSubRepo()
	svc := NewBillingService(repo, &mockBillingProvider{}, true)

	userID := uuid.New()
	seedSubscription(repo, userID, model.SubStatusCanceled, "stripe", "sub_canceled")

	if svc.IsActive(context.Background(), userID) {
		t.Error("expected IsActive=false for canceled subscription")
	}
}

func TestIsActiveExpiredSubscription(t *testing.T) {
	repo := newMockSubRepo()
	svc := NewBillingService(repo, &mockBillingProvider{}, true)

	userID := uuid.New()
	seedSubscription(repo, userID, model.SubStatusExpired, "apple", "sub_expired")

	if svc.IsActive(context.Background(), userID) {
		t.Error("expected IsActive=false for expired subscription")
	}
}

func TestIsActivePastDueSubscription(t *testing.T) {
	repo := newMockSubRepo()
	svc := NewBillingService(repo, &mockBillingProvider{}, true)

	userID := uuid.New()
	seedSubscription(repo, userID, model.SubStatusPastDue, "google", "sub_past_due")

	if svc.IsActive(context.Background(), userID) {
		t.Error("expected IsActive=false for past_due subscription")
	}
}

func TestIsActiveRepoError(t *testing.T) {
	repo := newMockSubRepo()
	repo.getErr = fmt.Errorf("db error")
	svc := NewBillingService(repo, &mockBillingProvider{}, true)

	if svc.IsActive(context.Background(), uuid.New()) {
		t.Error("expected IsActive=false when repo returns an error")
	}
}
