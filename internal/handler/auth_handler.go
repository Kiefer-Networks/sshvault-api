package handler

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/kiefernetworks/shellvault-server/internal/auth"
	"github.com/kiefernetworks/shellvault-server/internal/service"
)

type AuthHandler struct {
	authService *service.AuthService
	apple       auth.OAuthProvider
	google      auth.OAuthProvider
}

func NewAuthHandler(authService *service.AuthService, apple, google auth.OAuthProvider) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		apple:       apple,
		google:      google,
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

	resp, err := h.authService.Register(r.Context(), &req)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "already registered"):
			respondError(w, http.StatusConflict, msg)
		case strings.Contains(msg, "invalid email"):
			respondError(w, http.StatusBadRequest, msg)
		default:
			log.Error().Err(err).Msg("registration failed")
			respondError(w, http.StatusInternalServerError, "registration failed")
		}
		return
	}

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

	req.IP = r.RemoteAddr

	resp, err := h.authService.Login(r.Context(), &req)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}

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
	respondJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (h *AuthHandler) OAuth(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")

	var req service.OAuthRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.IDToken == "" {
		respondError(w, http.StatusBadRequest, "id_token is required")
		return
	}

	var oauthProvider auth.OAuthProvider
	switch provider {
	case "apple":
		oauthProvider = h.apple
	case "google":
		oauthProvider = h.google
	default:
		respondError(w, http.StatusBadRequest, "unsupported provider")
		return
	}

	if oauthProvider == nil {
		respondError(w, http.StatusNotImplemented, "OAuth provider not configured")
		return
	}

	resp, err := h.authService.OAuthLogin(r.Context(), oauthProvider, req.IDToken, req.DeviceName)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		respondError(w, http.StatusBadRequest, "token is required")
		return
	}

	if err := h.authService.VerifyEmail(r.Context(), token); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

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

	if err := h.authService.ResetPassword(r.Context(), req.Token, req.NewPassword); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "password reset successful"})
}
