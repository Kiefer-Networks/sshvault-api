package coupon

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/middleware"
	"github.com/rs/zerolog/log"
)

// Handler serves coupon redemption HTTP endpoints.
type Handler struct {
	service *Service
	audit   *audit.Logger
}

// NewHandler creates a coupon handler.
func NewHandler(service *Service, auditLogger *audit.Logger) *Handler {
	return &Handler{service: service, audit: auditLogger}
}

// Redeem handles POST /v1/billing/redeem.
func (h *Handler) Redeem(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	defer func() { _ = r.Body.Close() }()

	code := strings.TrimSpace(req.Code)
	if code == "" {
		respondError(w, http.StatusBadRequest, "code required")
		return
	}

	result, err := h.service.Redeem(r.Context(), userID, code)
	if err != nil {
		truncatedCode := code
		if len(truncatedCode) > 4 {
			truncatedCode = truncatedCode[:4] + "***"
		}
		log.Warn().Err(err).Str("user_id", userID.String()).Str("code", truncatedCode).Msg("coupon redemption failed")
		h.audit.LogFromRequest(r, audit.CatBilling, audit.ActCouponRedeem).
			Level(audit.LevelWarn).
			Detail("code", truncatedCode).
			Detail("error", err.Error()).
			Send()

		// Return curated error messages to avoid leaking internals.
		errMsg := err.Error()
		clientMsg := "failed to redeem coupon"
		if strings.Contains(errMsg, "not found") {
			clientMsg = "coupon not found"
		} else if strings.Contains(errMsg, "already redeemed") || strings.Contains(errMsg, "expired") {
			clientMsg = errMsg
		}
		respondError(w, http.StatusBadRequest, clientMsg)
		return
	}

	h.audit.LogFromRequest(r, audit.CatBilling, audit.ActCouponRedeem).
		Detail("code", code).
		Detail("sync_granted", result.SyncGranted).
		Detail("sync_days", result.SyncDays).
		Send()

	respondJSON(w, http.StatusOK, result)
}

func requireUserID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return uuid.Nil, false
	}
	return userID, true
}

func respondJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		if err := json.NewEncoder(w).Encode(data); err != nil {
			log.Error().Err(err).Msg("failed to encode JSON response")
		}
	}
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]string{"error": message})
}
