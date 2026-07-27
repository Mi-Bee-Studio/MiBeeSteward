// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package domain

import (
	"encoding/json"
	"time"
)

// ChannelType represents the type of notification channel.
type ChannelType string

const (
	ChannelTypeWebhook ChannelType = "webhook"
	ChannelTypeEmail   ChannelType = "email"
)

// Request types

type CreateChannelRequest struct {
	Name    string          `json:"name"`
	Type    ChannelType     `json:"type"`
	Config  json.RawMessage `json:"config"`
	Enabled *bool           `json:"enabled,omitempty"`
}

type UpdateChannelRequest struct {
	Name    *string          `json:"name,omitempty"`
	Type    *ChannelType     `json:"type,omitempty"`
	Config  *json.RawMessage `json:"config,omitempty"`
	Enabled *bool            `json:"enabled,omitempty"`
}

// Response types

type ChannelResponse struct {
	ID        int64           `json:"id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Config    json.RawMessage `json:"config"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type NotificationLogResponse struct {
	ID           int64     `json:"id"`
	RuleID       *int64    `json:"rule_id,omitempty"`
	ChannelID    *int64    `json:"channel_id,omitempty"`
	Status       string    `json:"status"`
	Payload      string    `json:"payload"`
	ErrorMessage string    `json:"error_message"`
	SentAt       time.Time `json:"sent_at"`
	// IsRead is per-user (the bell renders for every authenticated user, each
	// with an independent unread water mark). Drives unread styling + count.
	IsRead bool `json:"is_read"`
}

type ChannelListResponse struct {
	Channels []ChannelResponse `json:"channels"`
	Total    int               `json:"total"`
}

type NotificationLogListResponse struct {
	Logs []NotificationLogResponse `json:"logs"`
	// Total is the requesting user's UNREAD count (not the total log row count).
	// The field name is kept for backwards-compat with the existing frontend
	// NotificationBell consumer; the bell only ever needed the unread count.
	Total int `json:"total"`
}

// MarkAllReadResponse is returned by POST /notification/logs/read.
type MarkAllReadResponse struct {
	// Marked is the number of logs newly marked as read for the user.
	Marked int64 `json:"marked"`
}
