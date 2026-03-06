package handler

import (
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
			Detail("email", req.Email).
			Detail("error", err.Error()).
			Send()
		msg := err.Error()
		switch {
		case strings.Contains(msg, "already registered"):
			// Return a generic success to prevent email enumeration
			respondJSON(w, http.StatusCreated, map[string]string{"status": "registration successful"})
		case strings.Contains(msg, "invalid email"):
			respondError(w, http.StatusBadRequest, msg)
		default:
			log.Error().Err(err).Msg("registration failed")
			respondError(w, http.StatusInternalServerError, "registration failed")
		}
		return
	}

	h.audit.LogFromRequest(r, audit.CatAuth, audit.ActRegister).
		Actor(resp.User.ID, req.Email).
		Resource("user", resp.User.ID.String()).
		Send()
	respondJSON(w, http.StatusCreated, resp)
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
			Detail("email", req.Email).
			Send()
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

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		respondError(w, http.StatusBadRequest, "token is required")
		return
	}

	if err := h.authService.VerifyEmail(r.Context(), token); err != nil {
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
