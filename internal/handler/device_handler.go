package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/kiefernetworks/shellvault-server/internal/model"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
)

type DeviceHandler struct {
	deviceRepo repository.DeviceRepository
}

func NewDeviceHandler(deviceRepo repository.DeviceRepository) *DeviceHandler {
	return &DeviceHandler{
		deviceRepo: deviceRepo,
	}
}

func (h *DeviceHandler) RegisterDevice(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	var req struct {
		Name     string `json:"name"`
		Platform string `json:"platform"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		req.Name = "Unknown Device"
	}
	if req.Platform == "" {
		req.Platform = "unknown"
	}
	if len(req.Name) > 255 {
		respondError(w, http.StatusBadRequest, "name must be at most 255 characters")
		return
	}
	if len(req.Platform) > 50 {
		respondError(w, http.StatusBadRequest, "platform must be at most 50 characters")
		return
	}

	device := &model.Device{
		UserID:   userID,
		Name:     req.Name,
		Platform: req.Platform,
	}

	if err := h.deviceRepo.Create(r.Context(), device); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to register device")
		return
	}

	respondJSON(w, http.StatusCreated, map[string]any{
		"id":       device.ID,
		"name":     device.Name,
		"platform": device.Platform,
	})
}

func (h *DeviceHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	devices, err := h.deviceRepo.GetByUserID(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list devices")
		return
	}

	if devices == nil {
		respondJSON(w, http.StatusOK, map[string]any{"devices": []any{}})
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (h *DeviceHandler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	deviceID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid device id")
		return
	}

	if err := h.deviceRepo.Delete(r.Context(), deviceID, userID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete device")
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "device removed"})
}
