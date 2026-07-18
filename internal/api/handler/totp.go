// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/config"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/repository"
	"mibee-steward/internal/service"
)

// TOTPHandler handles HTTP requests for 2FA/TOTP endpoints.
type TOTPHandler struct {
	svc       *service.TOTPService
	userSvc   *service.UserService
	cfg       *config.Config
	auditRepo *repository.AuditRepository
}

// NewTOTPHandler creates a new TOTPHandler.
func NewTOTPHandler(svc *service.TOTPService, userSvc *service.UserService, cfg *config.Config, auditRepo *repository.AuditRepository) *TOTPHandler {
	return &TOTPHandler{svc: svc, userSvc: userSvc, cfg: cfg, auditRepo: auditRepo}
}

// Routes returns a Chi router with TOTP routes registered.
// These routes are mounted under /api/v1/auth/2fa with the login rate limiter.
func (h *TOTPHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /setup", h.Setup)
	mux.HandleFunc("POST /enable", h.Enable)
	mux.HandleFunc("POST /disable", h.Disable)
	mux.HandleFunc("POST /verify", h.Verify)
	mux.HandleFunc("GET /status", h.Status)
	return mux
}

// Setup handles POST /api/v1/auth/2fa/setup
// Requires authentication. Generates a new TOTP secret and backup codes.
func (h *TOTPHandler) Setup(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := middleware.GetUserFromContext(r)
	if !ok {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	profile, err := h.userSvc.GetProfile(r.Context(), userID)
	if err != nil {
		slog.Error("failed to get user profile for 2FA setup", "user_id", userID, "error", err)
		Error(w, http.StatusInternalServerError, "failed to setup 2FA")
		return
	}

	resp, err := h.svc.Setup(r.Context(), userID, profile.Username)
	if err != nil {
		slog.Error("2FA setup failed", "user_id", userID, "error", err)
		Error(w, http.StatusInternalServerError, "failed to setup 2FA")
		return
	}

	Created(w, resp)
}

// Enable handles POST /api/v1/auth/2fa/enable
// Requires authentication. Validates the TOTP code and enables 2FA.
func (h *TOTPHandler) Enable(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := middleware.GetUserFromContext(r)
	if !ok {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req domain.TOTPEnableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Code == "" {
		Error(w, http.StatusBadRequest, "code is required")
		return
	}

	err := h.svc.Enable(r.Context(), userID, req.Code)
	if err != nil {
		if errors.Is(err, service.ErrTOTPNotFound) {
			Error(w, http.StatusBadRequest, "2FA not set up. Please setup first.")
			return
		}
		if errors.Is(err, service.ErrInvalidTOTPCode) {
			Error(w, http.StatusUnprocessableEntity, "invalid TOTP code")
			return
		}
		slog.Error("2FA enable failed", "user_id", userID, "error", err)
		Error(w, http.StatusInternalServerError, "failed to enable 2FA")
		return
	}

	Success(w, map[string]string{"message": "2FA enabled successfully"})
}

// Disable handles POST /api/v1/auth/2fa/disable
// Requires authentication. Verifies password and removes 2FA.
func (h *TOTPHandler) Disable(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := middleware.GetUserFromContext(r)
	if !ok {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req domain.TOTPDisableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Password == "" {
		Error(w, http.StatusBadRequest, "password is required")
		return
	}

	err := h.svc.Disable(r.Context(), userID, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			Error(w, http.StatusNotFound, "user not found")
			return
		}
		if errors.Is(err, service.ErrTOTPInvalidPassword) {
			Error(w, http.StatusUnauthorized, "invalid password")
			return
		}
		slog.Error("2FA disable failed", "user_id", userID, "error", err)
		Error(w, http.StatusInternalServerError, "failed to disable 2FA")
		return
	}

	Success(w, map[string]string{"message": "2FA disabled successfully"})
}

// Verify handles POST /api/v1/auth/2fa/verify
// This endpoint receives a TOTP code after a login challenge.
// It validates the code and returns a JWT token on success.
// This is a public endpoint (no auth middleware) — the user proves identity via 2FA code.
func (h *TOTPHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var req domain.TOTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UserID <= 0 || req.Code == "" {
		Error(w, http.StatusBadRequest, "user_id and code are required")
		return
	}

	err := h.svc.Verify(r.Context(), req.UserID, req.Code)
	if err != nil {
		if errors.Is(err, service.ErrTOTPNotFound) {
			Error(w, http.StatusBadRequest, "2FA not configured")
			return
		}
		if errors.Is(err, service.ErrInvalidTOTPCode) {
			Error(w, http.StatusUnprocessableEntity, "invalid code")
			return
		}
		if errors.Is(err, service.ErrTOTPNotEnabled) {
			Error(w, http.StatusBadRequest, "2FA is not enabled")
			return
		}
		slog.Error("2FA verify failed", "user_id", req.UserID, "error", err)
		Error(w, http.StatusInternalServerError, "verification failed")
		return
	}

	// Code is valid — generate JWT token
	profile, err := h.userSvc.GetProfile(r.Context(), req.UserID)
	if err != nil {
		slog.Error("failed to get user profile for 2FA", "user_id", req.UserID, "error", err)
		Error(w, http.StatusInternalServerError, "verification failed")
		return
	}

	// Generate token via a direct call — we need to use GenerateTokenForUser
	// Since we can't access generateToken directly, use a public method
	token, err := h.userSvc.GenerateTokenForUser(req.UserID, profile.Role)
	if err != nil {
		slog.Error("failed to generate token for 2FA", "user_id", req.UserID, "error", err)
		Error(w, http.StatusInternalServerError, "verification failed")
		return
	}

	// Audit log
	userID := req.UserID
	h.auditRepo.Log(r.Context(), repository.AuditLog{
		UserID:       &userID,
		Action:       "auth.login.2fa.success",
		ResourceType: "user",
		ResourceID:   strconv.FormatInt(userID, 10),
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	})

	// Set cookie
	sameSite := http.SameSiteStrictMode
	if h.cfg.Auth.CookieSameSite == "lax" {
		sameSite = http.SameSiteLaxMode
	}
	cookieMaxAge := 86400
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   cookieMaxAge,
		HttpOnly: true,
		Secure:   h.cfg.Auth.CookieSecure,
		SameSite: sameSite,
		Domain:   h.cfg.Auth.CookieDomain,
	})

	Success(w, domain.LoginResponse{
		Token: token,
		User:  *profile,
	})
}

// Status handles GET /api/v1/auth/2fa/status
// Requires authentication.
func (h *TOTPHandler) Status(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := middleware.GetUserFromContext(r)
	if !ok {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	resp, err := h.svc.GetStatus(r.Context(), userID)
	if err != nil {
		slog.Error("failed to get 2FA status", "user_id", userID, "error", err)
		Error(w, http.StatusInternalServerError, "failed to get 2FA status")
		return
	}

	Success(w, resp)
}
