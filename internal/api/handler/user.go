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
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/config"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/repository"
	"mibee-steward/internal/service"
)

// UserHandler handles HTTP requests for user/auth endpoints.
type UserHandler struct {
	svc       *service.UserService
	cfg       *config.Config
	auditRepo *repository.AuditRepository
	blacklist *service.TokenBlacklist
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(svc *service.UserService, cfg *config.Config, auditRepo *repository.AuditRepository, blacklist *service.TokenBlacklist) *UserHandler {
	return &UserHandler{svc: svc, cfg: cfg, auditRepo: auditRepo, blacklist: blacklist}
}

// Routes returns a Chi router with all user/auth routes registered.
func (h *UserHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// Public routes
	r.Post("/login", h.Login)
	r.Post("/logout", h.Logout)
	r.With(middleware.RequireAdmin).Post("/register", h.Register)

	// Protected routes (RequireAuth)
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireAuth)
		r.Get("/profile", h.GetProfile)
		r.Put("/profile", h.UpdateProfile)
		r.Put("/password", h.ChangePassword)
		r.Put("/force-password", h.ForceChangePassword)
	})

	return r
}

// Login handles POST /api/v1/auth/login
func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		Error(w, http.StatusBadRequest, "username and password are required")
		return
	}

	resp, err := h.svc.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			slog.Warn("login failed", "username", req.Username, "ip", r.RemoteAddr, "reason", "invalid credentials")
			h.auditRepo.Log(r.Context(), repository.AuditLog{
				Action:       "auth.login.failure",
				ResourceType: "user",
				IPAddress:    r.RemoteAddr,
				UserAgent:    r.UserAgent(),
				Details:      "username=" + req.Username,
			})
			Error(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if errors.Is(err, service.ErrAccountLocked) {
			slog.Warn("login failed", "username", req.Username, "ip", r.RemoteAddr, "reason", "account locked")
			h.auditRepo.Log(r.Context(), repository.AuditLog{
				Action:       "auth.login.failure",
				ResourceType: "user",
				IPAddress:    r.RemoteAddr,
				UserAgent:    r.UserAgent(),
				Details:      "username=" + req.Username + " reason=account_locked",
			})
			Error(w, http.StatusTooManyRequests, "account is temporarily locked")
			return
		}
		slog.Warn("login failed", "username", req.Username, "ip", r.RemoteAddr, "reason", err.Error())
		h.auditRepo.Log(r.Context(), repository.AuditLog{
			Action:       "auth.login.failure",
			ResourceType: "user",
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
			Details:      "username=" + req.Username,
		})
		Error(w, http.StatusInternalServerError, "login failed")
		return
	}
	userID := resp.User.ID

	// If 2FA is required, return challenge without cookie/token
	if resp.TwoFactorRequired {
		Success(w, resp)
		slog.Info("login challenge: 2FA required", "username", req.Username, "ip", r.RemoteAddr)
		return
	}

	h.auditRepo.Log(r.Context(), repository.AuditLog{
		UserID:       &userID,
		Action:       "auth.login.success",
		ResourceType: "user",
		ResourceID:   strconv.FormatInt(userID, 10),
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	})

	// Set HttpOnly cookie
	sameSite := http.SameSiteStrictMode
	if h.cfg.Auth.CookieSameSite == "lax" {
		sameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    resp.Token,
		Path:     "/",
		MaxAge:   h.cookieMaxAge(),
		HttpOnly: true,
		Secure:   h.cfg.Auth.CookieSecure,
		SameSite: sameSite,
		Domain:   h.cfg.Auth.CookieDomain,
	})

	Success(w, resp)
	slog.Info("login success", "username", req.Username, "ip", r.RemoteAddr)
}

// Register handles POST /api/v1/auth/register (admin only)
func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req domain.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		Error(w, http.StatusBadRequest, "username, email, and password are required")
		return
	}

	resp, err := h.svc.Register(r.Context(), req.Username, req.Email, req.Password, req.Role)
	if err != nil {
		if errors.Is(err, service.ErrUserExists) {
			Error(w, http.StatusConflict, "user already exists")
			return
		}
		Error(w, http.StatusInternalServerError, "registration failed")
		return
	}
	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), repository.AuditLog{
			UserID:       &userID,
			Action:       "admin.user.create",
			ResourceType: "user",
			ResourceID:   strconv.FormatInt(resp.ID, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	Created(w, resp)
}

// Logout handles POST /api/v1/auth/logout
func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Extract and blacklist the token if present
	tokenStr := extractTokenFromRequest(r)
	if tokenStr != "" && h.blacklist != nil {
		tok, err := jwtauth.VerifyToken(middleware.GetJWTAuth(), tokenStr)
		if err == nil {
			var jti string
			if err := tok.Get("jti", &jti); err == nil && jti != "" {
				var exp float64
				if err := tok.Get("exp", &exp); err == nil {
					remaining := time.Until(time.Unix(int64(exp), 0))
					if remaining > 0 {
						h.blacklist.Add(jti, remaining)
					}
				}
			}
		}
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), repository.AuditLog{
			UserID:       &userID,
			Action:       "auth.logout",
			ResourceType: "user",
			ResourceID:   strconv.FormatInt(userID, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.Auth.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
	Success(w, map[string]string{"message": "logged out"})
}

// GetProfile handles GET /api/v1/auth/profile
func (h *UserHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := middleware.GetUserFromContext(r)
	if !ok {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	resp, err := h.svc.GetProfile(r.Context(), userID)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			Error(w, http.StatusNotFound, "user not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get profile")
		return
	}

	Success(w, resp)
}

// UpdateProfile handles PUT /api/v1/auth/profile
func (h *UserHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := middleware.GetUserFromContext(r)
	if !ok {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req domain.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" {
		Error(w, http.StatusBadRequest, "email is required")
		return
	}

	resp, err := h.svc.UpdateProfile(r.Context(), userID, req.Email)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			Error(w, http.StatusNotFound, "user not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to update profile")
		return
	}

	Success(w, resp)
}

// ChangePassword handles PUT /api/v1/auth/password
func (h *UserHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := middleware.GetUserFromContext(r)
	if !ok {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req domain.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.OldPassword == "" || req.NewPassword == "" {
		Error(w, http.StatusBadRequest, "old_password and new_password are required")
		return
	}

	err := h.svc.ChangePassword(r.Context(), userID, req.OldPassword, req.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			Error(w, http.StatusBadRequest, "incorrect current password")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to change password")
		return
	}

	Success(w, map[string]string{"message": "password changed"})
}

// ForceChangePassword handles PUT /api/v1/auth/force-password
func (h *UserHandler) ForceChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := middleware.GetUserFromContext(r)
	if !ok {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NewPassword == "" {
		Error(w, http.StatusBadRequest, "new_password is required")
		return
	}

	err := h.svc.ForceChangePassword(r.Context(), userID, req.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			Error(w, http.StatusNotFound, "user not found")
			return
		}
		Error(w, http.StatusBadRequest, err.Error())
		return
	}

	Success(w, map[string]string{"message": "password changed successfully"})
}

// ListUsers handles GET /api/v1/users (admin only)
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.ParseInt(r.URL.Query().Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)

	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	resp, err := h.svc.ListUsers(r.Context(), limit, offset)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	Success(w, resp)
}

// AdminResetPassword handles POST /api/v1/users/{id}/reset-password (admin only).
// An administrator resets another user's password. The target user is forced to
// change it again on next login (MustChangePassword=true), and any login
// lockout is cleared. This replaces the removed public forgot/reset-password
// flow: password recovery is an admin action, not a self-service email flow.
func (h *UserHandler) AdminResetPassword(w http.ResponseWriter, r *http.Request) {
	targetID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || targetID <= 0 {
		Error(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.NewPassword == "" {
		Error(w, http.StatusBadRequest, "new_password is required")
		return
	}

	if err := h.svc.AdminResetPassword(r.Context(), targetID, req.NewPassword); err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			Error(w, http.StatusNotFound, "user not found")
			return
		}
		Error(w, http.StatusBadRequest, err.Error())
		return
	}

	adminID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), repository.AuditLog{
			UserID:       &adminID,
			Action:       "admin.user.reset_password",
			ResourceType: "user",
			ResourceID:   strconv.FormatInt(targetID, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	Success(w, map[string]string{"message": "password reset successfully"})
}

// cookieMaxAge returns the cookie MaxAge in seconds.
// Precedence: CookieMaxAge config → TokenExpiry config → 86400 (24h default).
func (h *UserHandler) cookieMaxAge() int {
	// Try CookieMaxAge first
	if h.cfg.Auth.CookieMaxAge != "" {
		if d, err := time.ParseDuration(h.cfg.Auth.CookieMaxAge); err == nil {
			return int(d.Seconds())
		}
	}
	// Fallback to TokenExpiry
	if h.cfg.Auth.TokenExpiry != "" {
		if d, err := time.ParseDuration(h.cfg.Auth.TokenExpiry); err == nil {
			return int(d.Seconds())
		}
	}
	// Default 24h
	return 86400
}

// extractTokenFromRequest extracts the JWT token from cookie or Authorization header.
func extractTokenFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie("token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
