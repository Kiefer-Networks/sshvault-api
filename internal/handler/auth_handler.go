package handler

import (
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/kiefernetworks/shellvault-server/internal/audit"
	"github.com/kiefernetworks/shellvault-server/internal/service"
)

type AuthHandler struct {
	authService *service.AuthService
	audit       *audit.Logger
}

func NewAuthHandler(authService *service.AuthService, auditLogger *audit.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		audit:       auditLogger,
	}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req service.RegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	if len(req.Password) < MinPasswordLength {
		respondError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	if len(req.Password) > MaxPasswordLength {
		respondError(w, http.StatusBadRequest, "password must be at most 256 characters")
		return
	}

	resp, err := h.authService.Register(r.Context(), &req)
	if err != nil {
		h.audit.LogFromRequest(r, audit.CatAuth, audit.ActRegister).
			Level(audit.LevelWarn).
			Detail("email", "[redacted]").
			Send()
		msg := err.Error()
		switch {
		case strings.Contains(msg, "invalid email"):
			respondError(w, http.StatusBadRequest, msg)
		default:
			log.Error().Err(err).Msg("registration failed")
			respondError(w, http.StatusInternalServerError, "registration failed")
		}
		return
	}

	h.audit.LogFromRequest(r, audit.CatAuth, audit.ActRegister).
		Detail("email", "[redacted]").
		Send()
	respondJSON(w, http.StatusAccepted, resp)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req service.LoginRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		respondError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	req.IP = clientIP(r)

	resp, err := h.authService.Login(r.Context(), &req)
	if err != nil {
		h.audit.LogFromRequest(r, audit.CatAuth, audit.ActLoginFailed).
			Level(audit.LevelWarn).
			Detail("email", "[redacted]").
			Send()
		if errors.Is(err, service.ErrVerificationRequired) {
			respondError(w, http.StatusForbidden, "verification_required")
			return
		}
		respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	h.audit.LogFromRequest(r, audit.CatAuth, audit.ActLogin).
		Actor(resp.User.ID, resp.User.Email).
		Send()
	respondJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req service.RefreshRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RefreshToken == "" {
		respondError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	resp, err := h.authService.Refresh(r.Context(), &req)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	h.audit.LogFromRequest(r, audit.CatAuth, audit.ActRefreshToken).
		Actor(resp.User.ID, resp.User.Email).
		Send()
	respondJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.authService.Logout(r.Context(), req.RefreshToken); err != nil {
		log.Warn().Err(err).Msg("logout token revocation failed")
	}
	h.audit.LogFromRequest(r, audit.CatAuth, audit.ActLogout).Send()
	respondJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

var registrationPreview = template.Must(template.New("registration").Parse(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Activate your account</title></head><body>
<h1>Choose your SSHVault password</h1><p>To activate a new account, choose your own password. Opening this link does not activate the account. Existing accounts keep their current password.</p>
<form action="/v1/auth/verify-email" method="post"><input type="hidden" name="token" value="{{.}}"><label>New password <input type="password" name="new_password" autocomplete="new-password" minlength="8" maxlength="256" required></label><button type="submit">Verify email</button></form>
<p>If you do not want an account, close this page.</p></body></html>`))

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		token := r.URL.Query().Get("token")
		if token == "" {
			respondError(w, http.StatusBadRequest, "token is required")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		_ = registrationPreview.Execute(w, token)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		respondError(w, http.StatusMethodNotAllowed, "POST is required")
		return
	}
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			respondError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		req.Token = r.PostForm.Get("token")
		req.NewPassword = r.PostForm.Get("new_password")
	} else if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Token == "" || req.NewPassword == "" {
		respondError(w, http.StatusBadRequest, "token and new_password are required")
		return
	}
	if len(req.NewPassword) < MinPasswordLength || len(req.NewPassword) > MaxPasswordLength {
		respondError(w, http.StatusBadRequest, "password must be between 8 and 256 bytes")
		return
	}
	if err := h.authService.VerifyEmail(r.Context(), req.Token, req.NewPassword); err != nil {
		respondError(w, http.StatusBadRequest, "invalid or expired token")
		return
	}
	h.audit.LogFromRequest(r, audit.CatAuth, audit.ActVerifyEmail).Send()
	respondJSON(w, http.StatusOK, map[string]string{"status": "email verified"})
}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Fire-and-forget: always return success to prevent email enumeration
	if err := h.authService.ForgotPassword(r.Context(), req.Email); err != nil {
		log.Warn().Err(err).Msg("forgot password processing failed")
	}

	h.audit.LogFromRequest(r, audit.CatAuth, audit.ActForgotPassword).Send()
	respondJSON(w, http.StatusOK, map[string]string{"status": "if the email exists, a reset link has been sent"})
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Token == "" || req.NewPassword == "" {
		respondError(w, http.StatusBadRequest, "token and new_password are required")
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

	if err := h.authService.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		respondError(w, http.StatusBadRequest, "invalid or expired token")
		return
	}

	h.audit.LogFromRequest(r, audit.CatAuth, audit.ActResetPassword).Send()
	respondJSON(w, http.StatusOK, map[string]string{"status": "password reset successful"})
}

func (h *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}

	if err := h.authService.LogoutAll(r.Context(), userID); err != nil {
		log.Error().Err(err).Msg("logout-all failed")
		respondError(w, http.StatusInternalServerError, "failed to revoke sessions")
		return
	}

	h.audit.LogFromRequest(r, audit.CatAuth, audit.ActLogoutAll).Send()
	respondJSON(w, http.StatusOK, map[string]string{"status": "all sessions revoked"})
}
