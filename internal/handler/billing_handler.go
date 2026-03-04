package handler

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/service"
)

type BillingHandler struct {
	billingService *service.BillingService
	userService    *service.UserService
	audit          *audit.Logger
}

func NewBillingHandler(billingService *service.BillingService, userService *service.UserService, auditLogger *audit.Logger) *BillingHandler {
	return &BillingHandler{
		billingService: billingService,
		userService:    userService,
		audit:          auditLogger,
	}
}

func (h *BillingHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	status, err := h.billingService.GetStatus(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to get billing status")
		return
	}

	h.audit.LogFromRequest(r, audit.CatBilling, audit.ActStatusCheck).Send()
	respondJSON(w, http.StatusOK, status)
}

func (h *BillingHandler) CreateCheckout(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	user, err := h.userService.GetProfile(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	url, err := h.billingService.CreateCheckoutSession(r.Context(), userID, user.Email)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create checkout session")
		return
	}

	h.audit.LogFromRequest(r, audit.CatBilling, audit.ActCheckout).Send()
	respondJSON(w, http.StatusOK, map[string]string{"url": url})
}

func (h *BillingHandler) CreateTeleportCheckout(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	user, err := h.userService.GetProfile(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	url, err := h.billingService.CreateTeleportCheckoutSession(r.Context(), userID, user.Email)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create checkout session")
		return
	}

	h.audit.LogFromRequest(r, audit.CatBilling, audit.ActCheckout).
		Detail("product", "teleport_addon").
		Send()
	respondJSON(w, http.StatusOK, map[string]string{"url": url})
}

func (h *BillingHandler) CreatePortal(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	url, err := h.billingService.CreatePortalSession(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to create portal session")
		return
	}

	h.audit.LogFromRequest(r, audit.CatBilling, audit.ActPortal).Send()
	respondJSON(w, http.StatusOK, map[string]string{"url": url})
}

func (h *BillingHandler) StripeWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := readWebhookBody(r)
	if err != nil {
		respondError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	signature := r.Header.Get("Stripe-Signature")
	if err := h.billingService.HandleWebhook(r.Context(), "stripe", string(body), signature); err != nil {
		log.Warn().Err(err).Msg("stripe webhook processing failed")
		h.audit.LogFromRequest(r, audit.CatWebhook, audit.ActWebhookStripe).
			Level(audit.LevelWarn).
			Detail("error", err.Error()).
			Send()
	} else {
		h.audit.LogFromRequest(r, audit.CatWebhook, audit.ActWebhookStripe).Send()
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *BillingHandler) AppleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := readWebhookBody(r)
	if err != nil {
		respondError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	if err := h.billingService.HandleWebhook(r.Context(), "apple", string(body), ""); err != nil {
		log.Warn().Err(err).Msg("apple webhook processing failed")
		h.audit.LogFromRequest(r, audit.CatWebhook, audit.ActWebhookApple).
			Level(audit.LevelWarn).
			Detail("error", err.Error()).
			Send()
	} else {
		h.audit.LogFromRequest(r, audit.CatWebhook, audit.ActWebhookApple).Send()
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *BillingHandler) GoogleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := readWebhookBody(r)
	if err != nil {
		respondError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	if err := h.billingService.HandleWebhook(r.Context(), "google", string(body), ""); err != nil {
		log.Warn().Err(err).Msg("google webhook processing failed")
		h.audit.LogFromRequest(r, audit.CatWebhook, audit.ActWebhookGoogle).
			Level(audit.LevelWarn).
			Detail("error", err.Error()).
			Send()
	} else {
		h.audit.LogFromRequest(r, audit.CatWebhook, audit.ActWebhookGoogle).Send()
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *BillingHandler) VerifyGoogle(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	gp := h.billingService.GoogleProvider()
	if gp == nil {
		respondError(w, http.StatusServiceUnavailable, "Google Play billing not configured")
		return
	}

	var req struct {
		PurchaseToken string `json:"purchase_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PurchaseToken == "" {
		respondError(w, http.StatusBadRequest, "purchase_token required")
		return
	}

	sub, err := gp.VerifyAndUpsert(r.Context(), userID, req.PurchaseToken)
	if err != nil {
		log.Warn().Err(err).Str("user_id", userID.String()).Msg("google purchase verification failed")
		respondError(w, http.StatusBadGateway, "purchase verification failed")
		return
	}

	h.audit.LogFromRequest(r, audit.CatBilling, audit.ActCheckout).
		Detail("provider", "google").
		Detail("status", sub.Status).
		Send()

	respondJSON(w, http.StatusOK, map[string]any{
		"active":   sub.Status == "active",
		"provider": "google",
		"status":   sub.Status,
	})
}

func (h *BillingHandler) VerifyApple(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	ap := h.billingService.AppleProvider()
	if ap == nil {
		respondError(w, http.StatusServiceUnavailable, "Apple billing not configured")
		return
	}

	var req struct {
		TransactionID string `json:"transaction_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TransactionID == "" {
		respondError(w, http.StatusBadRequest, "transaction_id required")
		return
	}

	sub, err := ap.VerifyAndUpsert(r.Context(), userID, req.TransactionID)
	if err != nil {
		log.Warn().Err(err).Str("user_id", userID.String()).Msg("apple purchase verification failed")
		respondError(w, http.StatusBadGateway, "purchase verification failed")
		return
	}

	h.audit.LogFromRequest(r, audit.CatBilling, audit.ActCheckout).
		Detail("provider", "apple").
		Detail("status", sub.Status).
		Send()

	respondJSON(w, http.StatusOK, map[string]any{
		"active":   sub.Status == "active",
		"provider": "apple",
		"status":   sub.Status,
	})
}

func (h *BillingHandler) SuccessPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Payment Successful – ShellVault</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; color: #333; }
    .card { background: white; border-radius: 16px; padding: 48px; max-width: 420px; text-align: center; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
    .icon { font-size: 64px; margin-bottom: 16px; }
    h1 { font-size: 24px; margin: 0 0 8px; }
    p { color: #666; line-height: 1.6; margin: 8px 0; }
    .hint { font-size: 14px; color: #999; margin-top: 24px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">✅</div>
    <h1>Payment Successful</h1>
    <p>Your ShellVault Sync subscription is now active.</p>
    <p>You can close this tab and return to the app.</p>
    <p class="hint">Your subscription status will update automatically.</p>
  </div>
</body>
</html>`))
}

func (h *BillingHandler) CancelPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Payment Cancelled – ShellVault</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; color: #333; }
    .card { background: white; border-radius: 16px; padding: 48px; max-width: 420px; text-align: center; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
    .icon { font-size: 64px; margin-bottom: 16px; }
    h1 { font-size: 24px; margin: 0 0 8px; }
    p { color: #666; line-height: 1.6; margin: 8px 0; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">↩️</div>
    <h1>Payment Cancelled</h1>
    <p>No worries — you can activate Sync anytime from the app.</p>
    <p>You can close this tab and return to ShellVault.</p>
  </div>
</body>
</html>`))
}

// readWebhookBody reads and limits a webhook request body to 1 MB.
func readWebhookBody(r *http.Request) ([]byte, error) {
	defer func() { _ = r.Body.Close() }()
	return io.ReadAll(io.LimitReader(r.Body, 1<<20))
}
