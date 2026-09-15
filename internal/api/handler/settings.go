// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/config"
	"mibee-steward/internal/service"
	"mibee-steward/internal/version"
)

// SettingsHandler serves the settings center: runtime-editable configuration
// that overrides the YAML file (system_settings overlay, resolved overlay >
// YAML > defaults by the services that consume it). Today it covers the auth
// password policy and login lockout; /system exposes read-only instance info
// (version, network identity, vault status) so the common "what am I running
// and what did I forget to configure" check needs no SSH.
type SettingsHandler struct {
	settings  *service.SettingsService // nil-able: overlay load failure degrades writes, /system still works
	userSvc   *service.UserService
	cfg       *config.Config
	auditRepo *service.AuditRepository
}

func NewSettingsHandler(settings *service.SettingsService, userSvc *service.UserService, cfg *config.Config, auditRepo *service.AuditRepository) *SettingsHandler {
	return &SettingsHandler{settings: settings, userSvc: userSvc, cfg: cfg, auditRepo: auditRepo}
}

// authSettingsResponse is GET /api/v1/settings/auth — effective values plus
// where each came from, so the UI can show "edited in web UI" vs "from the
// config file".
type authSettingsResponse struct {
	PasswordPolicy       config.PasswordPolicyConfig `json:"password_policy"`
	PasswordPolicySource string                      `json:"password_policy_source"`
	Lockout              config.LockoutConfig        `json:"lockout"`
	LockoutSource        string                      `json:"lockout_source"`
}

// GetAuth handles GET /api/v1/settings/auth.
func (h *SettingsHandler) GetAuth(w http.ResponseWriter, _ *http.Request) {
	resp := authSettingsResponse{
		PasswordPolicy:       h.userSvc.EffectivePasswordPolicy(),
		PasswordPolicySource: "config",
		Lockout:              h.cfg.Auth.Lockout,
		LockoutSource:        "config",
	}
	if l := h.effectiveLockout(); l.MaxFailedAttempts > 0 {
		resp.Lockout = l
	}
	if h.settings != nil {
		if h.settings.Has(service.SettingAuthPasswordPolicy) {
			resp.PasswordPolicySource = "overlay"
		}
		if h.settings.Has(service.SettingAuthLockout) {
			resp.LockoutSource = "overlay"
		}
	}
	Success(w, resp)
}

func (h *SettingsHandler) effectiveLockout() config.LockoutConfig {
	// Resolve through the same precedence the login path uses. LockoutParams
	// applies the per-field fallbacks; mirror it for display.
	maxAttempts, lockMinutes := h.userSvc.LockoutParams()
	return config.LockoutConfig{MaxFailedAttempts: maxAttempts, LockMinutes: lockMinutes}
}

// updateAuthRequest is PUT /api/v1/settings/auth. Pointer fields make each
// section independently optional; a present section REPLACES the whole
// overlay value (no per-key merge — the UI always submits the full form).
type updateAuthRequest struct {
	PasswordPolicy *config.PasswordPolicyConfig `json:"password_policy,omitempty"`
	Lockout        *config.LockoutConfig        `json:"lockout,omitempty"`
}

// UpdateAuth handles PUT /api/v1/settings/auth (admin). Writes land in the
// system_settings overlay and take effect on the next password
// validation/login — no restart.
func (h *SettingsHandler) UpdateAuth(w http.ResponseWriter, r *http.Request) {
	if h.settings == nil {
		Error(w, http.StatusServiceUnavailable, "settings overlay unavailable (database load failed at startup)")
		return
	}

	var req updateAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.PasswordPolicy == nil && req.Lockout == nil {
		Error(w, http.StatusBadRequest, "nothing to update: password_policy or lockout is required")
		return
	}

	if req.PasswordPolicy != nil {
		p := *req.PasswordPolicy
		if p.MinLength < 1 || p.MinLength > 1024 {
			Error(w, http.StatusBadRequest, "password_policy.min_length must be between 1 and 1024")
			return
		}
		if err := h.settings.Set(r.Context(), service.SettingAuthPasswordPolicy, p); err != nil {
			slog.Error("settings: failed to persist password policy", "error", err)
			Error(w, http.StatusInternalServerError, "failed to save password policy")
			return
		}
	}
	if req.Lockout != nil {
		l := *req.Lockout
		if l.MaxFailedAttempts < 1 || l.MaxFailedAttempts > 1000 {
			Error(w, http.StatusBadRequest, "lockout.max_failed_attempts must be between 1 and 1000")
			return
		}
		if l.LockMinutes < 1 || l.LockMinutes > 10080 {
			Error(w, http.StatusBadRequest, "lockout.lock_minutes must be between 1 and 10080")
			return
		}
		if err := h.settings.Set(r.Context(), service.SettingAuthLockout, l); err != nil {
			slog.Error("settings: failed to persist lockout policy", "error", err)
			Error(w, http.StatusInternalServerError, "failed to save lockout policy")
			return
		}
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), service.AuditLog{
			UserID:       &userID,
			Action:       "admin.settings.auth",
			ResourceType: "settings",
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	// Return the effective post-update view so the UI doesn't need a refetch.
	h.GetAuth(w, r)
}

// GetSystem handles GET /api/v1/system — read-only instance facts.
func (h *SettingsHandler) GetSystem(w http.ResponseWriter, _ *http.Request) {
	Success(w, map[string]any{
		"version": version.Version,
		"network": map[string]string{
			"name": h.cfg.Network.Name,
			"cidr": h.cfg.Network.CIDR,
			"site": h.cfg.Network.Site,
		},
		"master_key_configured": h.cfg.Security.MasterKey != "",
		"demo_mode":             h.cfg.Server.DemoMode,
	})
}
