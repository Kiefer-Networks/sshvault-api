package handler

import (
	"encoding/base64"
	"html/template"
	"net/http"
	"strings"

	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/repository"
	"github.com/kiefernetworks/shellvault-server/internal/service"
)

type UserHandler struct {
	userService *service.UserService
	userRepo    repository.UserRepository
	audit       *audit.Logger
}

func NewUserHandler(userService *service.UserService, userRepo repository.UserRepository, auditLogger *audit.Logger) *UserHandler {
	return &UserHandler{userService: userService, userRepo: userRepo, audit: auditLogger}
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
	if req.Email != "" && service.NormalizeEmail(req.Email) != user.Email {
		respondJSON(w, http.StatusAccepted, map[string]string{"status": "pending_confirmation"})
		return
	}
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

	if len(req.NewPassword) > MaxPasswordLength {
		respondError(w, http.StatusBadRequest, "password must be at most 256 characters")
		return
	}

	if err := h.userService.ChangePassword(r.Context(), userID, &req); err != nil {
		respondError(w, http.StatusBadRequest, "failed to change password")
		return
	}

	h.audit.LogFromRequest(r, audit.CatUser, audit.ActPasswordChange).Send()
	respondJSON(w, http.StatusOK, map[string]string{"status": "password changed"})
}

const maxAvatarBase64Size = 512 * 1024
const maxAvatarDecodedSize = 256 * 1024

func (h *UserHandler) UpdateAvatar(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	var req struct {
		Avatar string `json:"avatar"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Avatar) > maxAvatarBase64Size {
		respondError(w, http.StatusRequestEntityTooLarge, "avatar must be at most 512 KB")
		return
	}

	if req.Avatar != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.Avatar)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid avatar encoding")
			return
		}
		if len(decoded) > maxAvatarDecodedSize {
			respondError(w, http.StatusBadRequest, "avatar too large")
			return
		}
		mime := http.DetectContentType(decoded)
		if !strings.HasPrefix(mime, "image/") {
			respondError(w, http.StatusBadRequest, "avatar must be an image")
			return
		}
	}

	user, err := h.userRepo.GetByID(r.Context(), userID)
	if err != nil || user == nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	user.Avatar = req.Avatar
	if err := h.userRepo.UpdateAvatar(r.Context(), user.ID, user.Avatar); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to update avatar")
		return
	}

	h.audit.LogFromRequest(r, audit.CatUser, audit.ActProfileUpdate).Send()
	respondJSON(w, http.StatusOK, user)
}

func (h *UserHandler) DeleteAvatar(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	user, err := h.userRepo.GetByID(r.Context(), userID)
	if err != nil || user == nil {
		respondError(w, http.StatusNotFound, "user not found")
		return
	}

	user.Avatar = ""
	if err := h.userRepo.UpdateAvatar(r.Context(), user.ID, user.Avatar); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete avatar")
		return
	}

	h.audit.LogFromRequest(r, audit.CatUser, audit.ActProfileUpdate).Send()
	respondJSON(w, http.StatusOK, map[string]string{"status": "avatar deleted"})
}

var emailChangePreview = template.Must(template.New("email-change").Parse(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Confirm email change</title></head><body>
<h1>Confirm your email change</h1><p>Confirming changes your recovery address and signs you out of all devices.</p>
<form action="/v1/auth/confirm-email-change" method="post"><input type="hidden" name="token" value="{{.}}"><button type="submit">Confirm email change</button></form>
<p>If you did not request this change, close this page.</p></body></html>`))

// PreviewEmailChange never consumes a token; link scanners cannot change account state.
func (h *UserHandler) PreviewEmailChange(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		respondError(w, http.StatusBadRequest, "token is required")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_ = emailChangePreview.Execute(w, token)
}
func (h *UserHandler) ConfirmEmailChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		respondError(w, http.StatusMethodNotAllowed, "POST is required")
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			respondError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		req.Token = r.PostForm.Get("token")
	} else if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Token == "" {
		respondError(w, http.StatusBadRequest, "token is required")
		return
	}
	if err := h.userService.ConfirmEmailChange(r.Context(), req.Token); err != nil {
		respondError(w, http.StatusBadRequest, "invalid or expired email change token")
		return
	}
	h.audit.LogFromRequest(r, audit.CatUser, audit.ActProfileUpdate).Send()
	respondJSON(w, http.StatusOK, map[string]string{"status": "email changed; sign in again"})
}
