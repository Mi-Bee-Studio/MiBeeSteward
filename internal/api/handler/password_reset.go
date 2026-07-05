package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
)

// PasswordResetHandler handles HTTP requests for password reset.
type PasswordResetHandler struct {
	svc *service.PasswordResetService
}

// NewPasswordResetHandler creates a new PasswordResetHandler.
func NewPasswordResetHandler(svc *service.PasswordResetService) *PasswordResetHandler {
	return &PasswordResetHandler{svc: svc}
}

// ForgotPassword handles POST /api/v1/auth/forgot-password
// Always returns 200 to prevent user enumeration.
func (h *PasswordResetHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req domain.ResetTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" {
		Error(w, http.StatusBadRequest, "email is required")
		return
	}

	// Always call the service — it returns nil even if email doesn't exist
	_ = h.svc.RequestReset(r.Context(), req.Email)

	Success(w, domain.ResetPasswordResponse{
		Message: "If the email exists, a reset link has been sent",
	})
}

// ResetPassword handles POST /api/v1/auth/reset-password
func (h *PasswordResetHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req domain.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Token == "" || req.NewPassword == "" {
		Error(w, http.StatusBadRequest, "token and new_password are required")
		return
	}

	err := h.svc.ResetPassword(r.Context(), req.Token, req.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrResetTokenInvalid) ||
			errors.Is(err, service.ErrResetTokenUsed) ||
			errors.Is(err, service.ErrResetTokenExpired) {
			Error(w, http.StatusBadRequest, err.Error())
			return
		}
		Error(w, http.StatusInternalServerError, "failed to reset password")
		return
	}

	Success(w, domain.ResetPasswordResponse{
		Message: "password has been reset successfully",
	})
}

// ValidateToken handles GET /api/v1/auth/reset-password/validate?token=...
func (h *PasswordResetHandler) ValidateToken(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		Error(w, http.StatusBadRequest, "token is required")
		return
	}

	err := h.svc.ValidateToken(r.Context(), token)
	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}

	Success(w, map[string]string{"message": "token is valid"})
}
