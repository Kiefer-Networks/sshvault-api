package handler

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/service"
	"github.com/rs/zerolog/log"
)

type VaultHandler struct {
	vaultService   *service.VaultService
	billingService *service.BillingService
	deviceRepo     repository.DeviceRepository
	audit          *audit.Logger
}

func NewVaultHandler(vaultService *service.VaultService, billingService *service.BillingService, deviceRepo repository.DeviceRepository, auditLogger *audit.Logger) *VaultHandler {
	return &VaultHandler{
		vaultService:   vaultService,
		billingService: billingService,
		deviceRepo:     deviceRepo,
		audit:          auditLogger,
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

	h.trackDevice(r)
	h.audit.LogFromRequest(r, audit.CatVault, audit.ActSyncPull).
		Resource("vault", userID.String()).
		Send()
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
		respondError(w, http.StatusBadRequest, "failed to update vault")
		return
	}

	h.trackDevice(r)
	h.audit.LogFromRequest(r, audit.CatVault, audit.ActSyncPush).
		Resource("vault", userID.String()).
		Detail("version", req.Version).
		Detail("blob_size", len(req.Blob)).
		Send()
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

	h.audit.LogFromRequest(r, audit.CatVault, audit.ActHistoryView).Send()
	respondJSON(w, http.StatusOK, map[string]any{"history": entries})
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
		respondError(w, http.StatusNotFound, "version not found")
		return
	}

	h.audit.LogFromRequest(r, audit.CatVault, audit.ActHistoryView).
		Detail("version", version).
		Send()
	respondJSON(w, http.StatusOK, resp)
}

func (h *VaultHandler) trackDevice(r *http.Request) {
	deviceIDStr := r.Header.Get("X-Device-ID")
	if deviceIDStr == "" {
		return
	}
	deviceID, err := uuid.Parse(deviceIDStr)
	if err != nil {
		return
	}
	if err := h.deviceRepo.UpdateLastSync(r.Context(), deviceID, r.RemoteAddr); err != nil {
		log.Warn().Err(err).Str("device_id", deviceIDStr).Msg("failed to track device sync")
	}
}
