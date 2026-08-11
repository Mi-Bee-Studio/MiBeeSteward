// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. A commercial license is available for use cases
// the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
)

// --- Notification Rule endpoints (#139) ---
//
// Methods on the same *NotificationHandler (declared in notification.go) so the
// rule routes share the handler's svc/auditRepo. Routes are admin-only and
// registered alongside the channel routes under /api/v1/notification/rules.

// CreateRule handles POST /api/v1/notification/rules.
func (h *NotificationHandler) CreateRule(w http.ResponseWriter, r *http.Request) {
	var req domain.CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Verify the referenced channel exists before creating the rule — a dangling
	// channel_id (ON DELETE CASCADE) would make the rule silently never fire.
	if _, err := h.svc.GetChannel(r.Context(), req.ChannelID); err != nil {
		if errors.Is(err, service.ErrChannelNotFound) {
			Error(w, http.StatusBadRequest, "referenced notification channel does not exist")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to verify notification channel")
		return
	}

	resp, err := h.svc.CreateRule(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidRuleConfig) {
			Error(w, http.StatusBadRequest, err.Error())
			return
		}
		Error(w, http.StatusInternalServerError, "failed to create notification rule")
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), service.AuditLog{
			UserID:       &userID,
			Action:       "admin.notification.rule.create",
			ResourceType: "notification_rule",
			ResourceID:   strconv.FormatInt(resp.ID, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	Created(w, resp)
}

// ListRules handles GET /api/v1/notification/rules.
func (h *NotificationHandler) ListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.svc.ListRules(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list notification rules")
		return
	}
	Success(w, domain.RuleListResponse{Rules: rules, Total: len(rules)})
}

// GetRule handles GET /api/v1/notification/rules/{id}.
func (h *NotificationHandler) GetRule(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}
	resp, err := h.svc.GetRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrRuleNotFound) {
			Error(w, http.StatusNotFound, "notification rule not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get notification rule")
		return
	}
	Success(w, resp)
}

// UpdateRule handles PUT /api/v1/notification/rules/{id} (full-replace).
func (h *NotificationHandler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}
	var req domain.UpdateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if _, err := h.svc.GetChannel(r.Context(), req.ChannelID); err != nil {
		if errors.Is(err, service.ErrChannelNotFound) {
			Error(w, http.StatusBadRequest, "referenced notification channel does not exist")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to verify notification channel")
		return
	}

	resp, err := h.svc.UpdateRule(r.Context(), id, req)
	if err != nil {
		if errors.Is(err, service.ErrRuleNotFound) {
			Error(w, http.StatusNotFound, "notification rule not found")
			return
		}
		if errors.Is(err, service.ErrInvalidRuleConfig) {
			Error(w, http.StatusBadRequest, err.Error())
			return
		}
		Error(w, http.StatusInternalServerError, "failed to update notification rule")
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), service.AuditLog{
			UserID:       &userID,
			Action:       "admin.notification.rule.update",
			ResourceType: "notification_rule",
			ResourceID:   strconv.FormatInt(id, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	Success(w, resp)
}

// SetRuleEnabled handles PATCH /api/v1/notification/rules/{id} (toggle only).
func (h *NotificationHandler) SetRuleEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}
	var req domain.SetRuleEnabledRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.svc.SetRuleEnabled(r.Context(), id, req.Enabled)
	if err != nil {
		if errors.Is(err, service.ErrRuleNotFound) {
			Error(w, http.StatusNotFound, "notification rule not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to toggle notification rule")
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), service.AuditLog{
			UserID:       &userID,
			Action:       "admin.notification.rule.enable",
			ResourceType: "notification_rule",
			ResourceID:   strconv.FormatInt(id, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	Success(w, resp)
}

// DeleteRule handles DELETE /api/v1/notification/rules/{id}.
func (h *NotificationHandler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}
	if err := h.svc.DeleteRule(r.Context(), id); err != nil {
		Error(w, http.StatusInternalServerError, "failed to delete notification rule")
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), service.AuditLog{
			UserID:       &userID,
			Action:       "admin.notification.rule.delete",
			ResourceType: "notification_rule",
			ResourceID:   strconv.FormatInt(id, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	w.WriteHeader(http.StatusNoContent)
}
