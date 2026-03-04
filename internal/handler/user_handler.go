package handler

import (
	"net/http"

	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/service"
)

type UserHandler struct {
	userService *service.UserService
	audit       *audit.Logger
}

func NewUserHandler(userService *service.UserService, auditLogger *audit.Logger) *UserHandler {
	return &UserHandler{userService: userService, audit: auditLogger}
}

func (h *UserHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	user, err := h.userService.GetProfile(r.Context(), userID)
	if err != nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	h.audit.LogFromRequest(r, audit.CatUser, audit.ActProfileView).Send()
	respondJSON(w, http.StatusOK, user)
}

func (h *UserHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	var req service.UpdateProfileRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Email) > 254 {
		respondError(w, http.StatusBadRequest, "email must be at most 254 characters")
		return
	}

	user, err := h.userService.UpdateProfile(r.Context(), userID, &req)
	if err != nil {
		respondError(w, http.StatusBadRequest, "failed to update profile")
		return
	}

	h.audit.LogFromRequest(r, audit.CatUser, audit.ActProfileUpdate).Send()
	respondJSON(w, http.StatusOK, user)
}

func (h *UserHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	if err := h.userService.DeleteAccount(r.Context(), userID); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete account")
		return
	}

	h.audit.LogFromRequest(r, audit.CatUser, audit.ActAccountDelete).
		Level(audit.LevelWarn).
		Send()
	respondJSON(w, http.StatusAccepted, map[string]string{
		"status":  "account scheduled for deletion",
		"message": "Your account and data will be permanently deleted in 30 days.",
	})
}

func (h *UserHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	var req service.ChangePasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CurrentPassword == "" {
		respondError(w, http.StatusBadRequest, "current_password is required")
		return
	}

	if len(req.NewPassword) < MinPasswordLength {
		respondError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	if err := h.userService.ChangePassword(r.Context(), userID, &req); err != nil {
		respondError(w, http.StatusBadRequest, "failed to change password")
		return
	}

	h.audit.LogFromRequest(r, audit.CatUser, audit.ActPasswordChange).Send()
	respondJSON(w, http.StatusOK, map[string]string{"status": "password changed"})
}
