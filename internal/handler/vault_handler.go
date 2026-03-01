package handler

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/kiefernetworks/shellvault-server/internal/service"
)

type VaultHandler struct {
	vaultService   *service.VaultService
	billingService *service.BillingService
}

func NewVaultHandler(vaultService *service.VaultService, billingService *service.BillingService) *VaultHandler {
	return &VaultHandler{
		vaultService:   vaultService,
		billingService: billingService,
	}
}

func (h *VaultHandler) GetVault(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	if !h.billingService.IsActive(r.Context(), userID) {
		respondError(w, http.StatusPaymentRequired, "active subscription required")
		return
	}

	resp, err := h.vaultService.GetVault(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to get vault")
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

func (h *VaultHandler) PutVault(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	if !h.billingService.IsActive(r.Context(), userID) {
		respondError(w, http.StatusPaymentRequired, "active subscription required")
		return
	}

	var req service.PutVaultRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Version < 1 {
		respondError(w, http.StatusBadRequest, "version must be >= 1")
		return
	}

	if len(req.Blob) == 0 {
		respondError(w, http.StatusBadRequest, "blob is required")
		return
	}

	if req.Checksum == "" {
		respondError(w, http.StatusBadRequest, "checksum is required")
		return
	}

	resp, err := h.vaultService.PutVault(r.Context(), userID, &req)
	if err != nil {
		if conflict, ok := err.(*service.ConflictError); ok {
			respondJSON(w, http.StatusConflict, conflict)
			return
		}
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

func (h *VaultHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	entries, err := h.vaultService.GetHistory(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to get history")
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{"history": entries})
}

func (h *VaultHandler) GetHistoryVersion(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	versionStr := chi.URLParam(r, "version")
	version, err := strconv.Atoi(versionStr)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid version")
		return
	}

	resp, err := h.vaultService.GetHistoryVersion(r.Context(), userID, version)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, resp)
}
