package handler

import (
	"io"
	"net/http"

	"github.com/kiefernetworks/shellvault-server/internal/middleware"
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
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
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
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
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
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
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
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB limit
	if err != nil {
		respondError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	defer r.Body.Close()

	signature := r.Header.Get("Stripe-Signature")
	if err := h.billingService.HandleWebhook(r.Context(), "stripe", string(body), signature); err != nil {
		respondError(w, http.StatusBadRequest, "webhook processing failed")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *BillingHandler) AppleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		respondError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	defer r.Body.Close()

	if err := h.billingService.HandleWebhook(r.Context(), "apple", string(body), ""); err != nil {
		respondError(w, http.StatusBadRequest, "webhook processing failed")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *BillingHandler) GoogleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		respondError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	defer r.Body.Close()

	if err := h.billingService.HandleWebhook(r.Context(), "google", string(body), ""); err != nil {
		respondError(w, http.StatusBadRequest, "webhook processing failed")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
