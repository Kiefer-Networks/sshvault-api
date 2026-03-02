package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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
		respondJSON(w, http.StatusOK, map[string]interface{}{"devices": []interface{}{}})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{"devices": devices})
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
