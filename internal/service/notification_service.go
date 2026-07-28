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
		return nil, fmt.Errorf("channel name is required")
	}
	if req.Type != domain.ChannelTypeWebhook && req.Type != domain.ChannelTypeEmail {
		return nil, fmt.Errorf("invalid channel type: %s", req.Type)
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
