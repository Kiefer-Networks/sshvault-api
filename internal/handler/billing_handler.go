package handler

import (
	"io"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/kiefernetworks/shellvault-server/internal/service"
)

type BillingHandler struct {
	billingService *service.BillingService
	userService    *service.UserService
}

func NewBillingHandler(billingService *service.BillingService, userService *service.UserService) *BillingHandler {
	return &BillingHandler{
		billingService: billingService,
		userService:    userService,
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
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"url": url})
}

func (h *BillingHandler) CreatePortal(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	url, err := h.billingService.CreatePortalSession(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

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
		respondError(w, http.StatusBadRequest, "webhook processing failed")
		return
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
		respondError(w, http.StatusBadRequest, "webhook processing failed")
		return
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
		respondError(w, http.StatusBadRequest, "webhook processing failed")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readWebhookBody reads and limits a webhook request body to 1 MB.
func readWebhookBody(r *http.Request) ([]byte, error) {
	defer func() { _ = r.Body.Close() }()
	return io.ReadAll(io.LimitReader(r.Body, 1<<20))
}
