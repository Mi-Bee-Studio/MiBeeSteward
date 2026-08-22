// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

var (
	ErrChannelNotFound = errors.New("notification channel not found")
	// ErrInvalidChannelConfig / ErrInvalidRuleConfig are category sentinels for
	// channel/rule field validation. Each wraps the specific rule as detail so
	// handlers map the whole family to 400 via errors.Is. (#165)
	ErrInvalidChannelConfig = errors.New("invalid notification channel configuration")
	ErrInvalidRuleConfig    = errors.New("invalid notification rule configuration")
)

// NotificationService handles notification channel and log business logic.
// (Alert-rule CRUD was removed: MiBee Steward does not build alerting — see
// AGENTS.md product vision. Notification channels are retained as neutral
// infrastructure for future non-alert dispatch use cases.)
type NotificationService struct {
	q *db.Queries
}

// NewNotificationService creates a new NotificationService.
func NewNotificationService(q *db.Queries) *NotificationService {
	return &NotificationService{q: q}
}

// --- Channel CRUD ---

// CreateChannel validates and creates a new notification channel.
func (s *NotificationService) CreateChannel(ctx context.Context, req domain.CreateChannelRequest) (*domain.ChannelResponse, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidChannelConfig)
	}
	if !domain.IsValidChannelType(req.Type) {
		return nil, fmt.Errorf("%w: invalid type %q", ErrInvalidChannelConfig, req.Type)
	}

	enabled := int64(1)
	if req.Enabled != nil && !*req.Enabled {
		enabled = 0
	}

	ch, err := s.q.CreateChannel(ctx, db.CreateChannelParams{
		Name:    req.Name,
		Type:    string(req.Type),
		Config:  string(req.Config),
		Enabled: enabled,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create channel: %w", err)
	}

	resp := toChannelResponse(ch)
	return &resp, nil
}

// GetChannel retrieves a notification channel by ID.
func (s *NotificationService) GetChannel(ctx context.Context, id int64) (*domain.ChannelResponse, error) {
	ch, err := s.q.GetChannelByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrChannelNotFound
		}
		return nil, fmt.Errorf("failed to get channel: %w", err)
	}

	resp := toChannelResponse(ch)
	return &resp, nil
}

// ListChannels returns all notification channels.
func (s *NotificationService) ListChannels(ctx context.Context) ([]domain.ChannelResponse, error) {
	channels, err := s.q.ListChannels(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list channels: %w", err)
	}

	result := make([]domain.ChannelResponse, len(channels))
	for i, ch := range channels {
		result[i] = toChannelResponse(ch)
	}
	return result, nil
}

// UpdateChannel updates an existing notification channel.
func (s *NotificationService) UpdateChannel(ctx context.Context, id int64, req domain.UpdateChannelRequest) (*domain.ChannelResponse, error) {
	existing, err := s.q.GetChannelByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrChannelNotFound
		}
		return nil, fmt.Errorf("failed to get channel: %w", err)
	}

	name := existing.Name
	if req.Name != nil {
		name = *req.Name
	}

	chType := existing.Type
	if req.Type != nil {
		if !domain.IsValidChannelType(*req.Type) {
			return nil, fmt.Errorf("%w: invalid type %q", ErrInvalidChannelConfig, *req.Type)
		}
		chType = string(*req.Type)
	}

	config := existing.Config
	if req.Config != nil {
		config = string(*req.Config)
	}

	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = int64(0)
		if *req.Enabled {
			enabled = 1
		}
	}

	ch, err := s.q.UpdateChannel(ctx, db.UpdateChannelParams{
		Name:    name,
		Type:    chType,
		Config:  config,
		Enabled: enabled,
		ID:      id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update channel: %w", err)
	}

	resp := toChannelResponse(ch)
	return &resp, nil
}

// SetChannelEnabled toggles a channel's enabled flag via a single-field UPDATE
// (no name/type/config are rewritten). This is the backend for the dedicated
// PATCH /channels/{id} endpoint, used by the UI toggle — it keeps the toggle
// path from ever re-writing the masked SMTP password back to the DB.
func (s *NotificationService) SetChannelEnabled(ctx context.Context, id int64, enabled bool) (*domain.ChannelResponse, error) {
	// Probe existence first so the caller gets the same ErrChannelNotFound → 404
	// semantics as UpdateChannel (SetChannelEnabled SQL would otherwise return
	// sql.ErrNoRows on the RETURNING scan, indistinguishable from a generic error).
	if _, err := s.q.GetChannelByID(ctx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrChannelNotFound
		}
		return nil, fmt.Errorf("failed to get channel: %w", err)
	}

	enabledInt := int64(0)
	if enabled {
		enabledInt = 1
	}
	ch, err := s.q.SetChannelEnabled(ctx, db.SetChannelEnabledParams{
		Enabled: enabledInt,
		ID:      id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to set channel enabled: %w", err)
	}

	resp := toChannelResponse(ch)
	return &resp, nil
}

// DeleteChannel deletes a notification channel by ID.
func (s *NotificationService) DeleteChannel(ctx context.Context, id int64) error {
	err := s.q.DeleteChannel(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete channel: %w", err)
	}
	return nil
}

// --- Notification Rule CRUD (#139) ---

var ErrRuleNotFound = errors.New("notification rule not found")

// CreateRule validates and creates a new notification rule. The caller
// (handler) is responsible for verifying the channel exists; this method only
// validates the rule's own fields.
func (s *NotificationService) CreateRule(ctx context.Context, req domain.CreateRuleRequest) (*domain.RuleResponse, error) {
	if err := validateRuleFields(req.EventType, req.ScopeType, req.Name, req.ChannelID, req.ScopeNetworkID, req.ScopeDeviceUUID); err != nil {
		return nil, err
	}
	rule, err := s.q.CreateNotificationRule(ctx, db.CreateNotificationRuleParams{
		Name:            req.Name,
		EventType:       req.EventType,
		ScopeType:       req.ScopeType,
		ScopeNetworkID:  req.ScopeNetworkID,
		ScopeDeviceUuid: req.ScopeDeviceUUID,
		ChannelID:       req.ChannelID,
		CooldownMinutes: normalizeCooldown(req.CooldownMinutes),
		Enabled:         1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create notification rule: %w", err)
	}
	resp := toRuleResponse(rule)
	return &resp, nil
}

// GetRule retrieves a notification rule by ID.
func (s *NotificationService) GetRule(ctx context.Context, id int64) (*domain.RuleResponse, error) {
	rule, err := s.q.GetNotificationRule(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRuleNotFound
		}
		return nil, fmt.Errorf("failed to get notification rule: %w", err)
	}
	resp := toRuleResponse(rule)
	return &resp, nil
}

// ListRules returns all notification rules (newest first).
func (s *NotificationService) ListRules(ctx context.Context) ([]domain.RuleResponse, error) {
	rules, err := s.q.ListNotificationRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list notification rules: %w", err)
	}
	out := make([]domain.RuleResponse, 0, len(rules))
	for _, r := range rules {
		out = append(out, toRuleResponse(r))
	}
	return out, nil
}

// UpdateRule replaces a rule's mutable fields (full-replace, like UpdateChannel).
func (s *NotificationService) UpdateRule(ctx context.Context, id int64, req domain.UpdateRuleRequest) (*domain.RuleResponse, error) {
	if err := validateRuleFields(req.EventType, req.ScopeType, req.Name, req.ChannelID, req.ScopeNetworkID, req.ScopeDeviceUUID); err != nil {
		return nil, err
	}
	rule, err := s.q.UpdateNotificationRule(ctx, db.UpdateNotificationRuleParams{
		Name:            req.Name,
		EventType:       req.EventType,
		ScopeType:       req.ScopeType,
		ScopeNetworkID:  req.ScopeNetworkID,
		ScopeDeviceUuid: req.ScopeDeviceUUID,
		ChannelID:       req.ChannelID,
		CooldownMinutes: normalizeCooldown(req.CooldownMinutes),
		ID:              id,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRuleNotFound
		}
		return nil, fmt.Errorf("failed to update notification rule: %w", err)
	}
	resp := toRuleResponse(rule)
	return &resp, nil
}

// SetRuleEnabled toggles a rule's enabled flag (single-field UPDATE).
func (s *NotificationService) SetRuleEnabled(ctx context.Context, id int64, enabled bool) (*domain.RuleResponse, error) {
	en := int64(0)
	if enabled {
		en = 1
	}
	rule, err := s.q.SetNotificationRuleEnabled(ctx, db.SetNotificationRuleEnabledParams{Enabled: en, ID: id})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRuleNotFound
		}
		return nil, fmt.Errorf("failed to toggle notification rule: %w", err)
	}
	resp := toRuleResponse(rule)
	return &resp, nil
}

// DeleteRule removes a notification rule.
func (s *NotificationService) DeleteRule(ctx context.Context, id int64) error {
	if err := s.q.DeleteNotificationRule(ctx, id); err != nil {
		return fmt.Errorf("failed to delete notification rule: %w", err)
	}
	return nil
}

// ListEnabledRulesByEventType loads enabled rules matching an event type. Used
// by the RuleEngine hot path (change event → candidate rules).
func (s *NotificationService) ListEnabledRulesByEventType(ctx context.Context, eventType string) ([]db.NotificationRule, error) {
	return s.q.ListEnabledRulesByEventType(ctx, eventType)
}

// validateRuleFields checks the cross-field constraints shared by create/update.
// Channel existence is NOT checked here (the handler does it so it can return a
// 409/400 with a channel-specific message before touching the DB).
func validateRuleFields(eventType, scopeType, name string, channelID int64, networkID *int64, deviceUUID string) error {
	if name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidRuleConfig)
	}
	if !domain.IsValidRuleEventType(eventType) {
		return fmt.Errorf("%w: invalid event_type %q", ErrInvalidRuleConfig, eventType)
	}
	if !domain.IsValidRuleScopeType(scopeType) {
		return fmt.Errorf("%w: invalid scope_type %q", ErrInvalidRuleConfig, scopeType)
	}
	if channelID <= 0 {
		return fmt.Errorf("%w: channel_id is required", ErrInvalidRuleConfig)
	}
	switch scopeType {
	case domain.RuleScopeNetwork:
		if networkID == nil || *networkID <= 0 {
			return fmt.Errorf("%w: scope_network_id is required when scope_type=network", ErrInvalidRuleConfig)
		}
	case domain.RuleScopeDevice:
		if deviceUUID == "" {
			return fmt.Errorf("%w: scope_device_uuid is required when scope_type=device", ErrInvalidRuleConfig)
		}
	}
	return nil
}

// normalizeCooldown clamps cooldown to [1, 10080] minutes (1 min … 7 days).
// 0 would mean "no cooldown" which defeats the anti-flap purpose; a very large
// value effectively disables the rule.
func normalizeCooldown(minutes int) int64 {
	if minutes <= 0 {
		return 30 // default
	}
	if minutes > 10080 {
		return 10080
	}
	return int64(minutes)
}

func toRuleResponse(r db.NotificationRule) domain.RuleResponse {
	return domain.RuleResponse{
		ID:              r.ID,
		Name:            r.Name,
		EventType:       r.EventType,
		ScopeType:       r.ScopeType,
		ScopeNetworkID:  r.ScopeNetworkID,
		ScopeDeviceUUID: r.ScopeDeviceUuid,
		ChannelID:       r.ChannelID,
		CooldownMinutes: int(r.CooldownMinutes),
		Enabled:         r.Enabled == 1,
		LastTriggeredAt: r.LastTriggeredAt,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
	}
}

// --- Notification Logs ---

// ListNotificationLogs returns notification logs with pagination.
// NOTE: this is the legacy system-wide view (no per-user read state). The
// header bell uses ListNotificationLogsForUser instead; this is kept for any
// future admin/audit consumer that wants the raw delivery log.
func (s *NotificationService) ListNotificationLogs(ctx context.Context, limit, offset int64) ([]domain.NotificationLogResponse, int64, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	total, err := s.q.CountNotificationLogs(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count notification logs: %w", err)
	}

	logs, err := s.q.ListNotificationLogs(ctx, db.ListNotificationLogsParams{
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list notification logs: %w", err)
	}

	result := make([]domain.NotificationLogResponse, len(logs))
	for i, log := range logs {
		// Legacy view has no per-user read state; treat all as read.
		result[i] = toNotificationLogResponse(log, true)
	}
	return result, total, nil
}

// ListNotificationLogsForUser returns the most recent notification logs for a
// user, each annotated with that user's is_read flag, plus the user's unread
// count. This is what the header bell consumes: the list for the dropdown and
// the unread count for the badge.
func (s *NotificationService) ListNotificationLogsForUser(ctx context.Context, userID, limit, offset int64) ([]domain.NotificationLogResponse, int64, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	unread, err := s.q.CountUnreadNotificationLogsForUser(ctx, userID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count unread notification logs: %w", err)
	}

	rows, err := s.q.ListNotificationLogsForUser(ctx, db.ListNotificationLogsForUserParams{
		UserID: userID,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list notification logs for user: %w", err)
	}

	result := make([]domain.NotificationLogResponse, len(rows))
	for i, row := range rows {
		result[i] = domain.NotificationLogResponse{
			ID:           row.ID,
			RuleID:       row.RuleID,
			ChannelID:    row.ChannelID,
			Status:       row.Status,
			Payload:      row.Payload,
			ErrorMessage: row.ErrorMessage,
			SentAt:       row.SentAt,
			IsRead:       row.IsRead,
		}
	}
	return result, unread, nil
}

// MarkAllNotificationLogsRead marks every currently-unread notification log as
// read for the user (idempotent). Returns the number of logs newly marked.
func (s *NotificationService) MarkAllNotificationLogsRead(ctx context.Context, userID int64) (int64, error) {
	n, err := s.q.MarkAllNotificationLogsRead(ctx, db.MarkAllNotificationLogsReadParams{
		UserID:   userID,
		UserID_2: userID,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to mark notification logs as read: %w", err)
	}
	return n, nil
}

// --- Response transformers ---

func toChannelResponse(ch db.NotificationChannel) domain.ChannelResponse {
	return domain.ChannelResponse{
		ID:        ch.ID,
		Name:      ch.Name,
		Type:      ch.Type,
		Config:    json.RawMessage(ch.Config),
		Enabled:   ch.Enabled == 1,
		CreatedAt: ch.CreatedAt,
		UpdatedAt: ch.UpdatedAt,
	}
}

func toNotificationLogResponse(log db.NotificationLog, isRead bool) domain.NotificationLogResponse {
	return domain.NotificationLogResponse{
		ID:           log.ID,
		RuleID:       log.RuleID,
		ChannelID:    log.ChannelID,
		Status:       log.Status,
		Payload:      log.Payload,
		ErrorMessage: log.ErrorMessage,
		SentAt:       log.SentAt,
		IsRead:       isRead,
	}
}
