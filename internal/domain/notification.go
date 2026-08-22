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
	ChannelTypeWebhook  ChannelType = "webhook"
	ChannelTypeEmail    ChannelType = "email"
	ChannelTypeFeishu   ChannelType = "feishu"   // 飞书/Lark custom bot (optional HMAC sign)
	ChannelTypeWeCom    ChannelType = "wecom"    // 企业微信群机器人
	ChannelTypeTelegram ChannelType = "telegram" // Bot API sendMessage
	ChannelTypeDiscord  ChannelType = "discord"  // incoming webhook
)

// IsValidChannelType reports whether t is a channel type the notification
// stack can build a Sender for (see notification.defaultSenderFactory).
func IsValidChannelType(t ChannelType) bool {
	switch t {
	case ChannelTypeWebhook, ChannelTypeEmail, ChannelTypeFeishu,
		ChannelTypeWeCom, ChannelTypeTelegram, ChannelTypeDiscord:
		return true
	}
	return false
}

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

// SetChannelEnabledRequest is the body of the dedicated
// PATCH /notification/channels/{id} toggle endpoint. Unlike the generic PUT
// (UpdateChannelRequest), it changes only `enabled` — server-side this routes
// to a single-field UPDATE so name/type/config are never touched. This avoids
// the data-corruption footgun where a client GET-then-PUT with a full body
// would write the masked SMTP password (`"*****"`) back over the real one.
type SetChannelEnabledRequest struct {
	Enabled bool `json:"enabled"`
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

// --- Notification rules (#139) ---
//
// A rule binds a change-detection event type (device_lost/recovered/added/
// changed) to a delivery channel with an optional scope filter and per-rule
// cooldown. The RuleEngine subscribes to changedetect.Watcher and dispatches
// matching rules via notification.Dispatcher.

// RuleEventType enumerates the change_log.change_type values a rule may match.
// These mirror changedetect.ChangeTypeDevice* constants (kept as strings here
// so the API layer has no dependency on the changedetect package).
const (
	RuleEventTypeDeviceLost      = "device_lost"
	RuleEventTypeDeviceRecovered = "device_recovered"
	RuleEventTypeDeviceAdded     = "device_added"
	RuleEventTypeDeviceChanged   = "device_changed"
)

// RuleScopeType controls which devices a rule applies to.
const (
	RuleScopeAll     = "all"     // every device (any network)
	RuleScopeNetwork = "network" // devices in scope_network_id
	RuleScopeDevice  = "device"  // the single device identified by scope_device_uuid
)

// IsValidRuleEventType reports whether t is a supported event_type value.
func IsValidRuleEventType(t string) bool {
	switch t {
	case RuleEventTypeDeviceLost, RuleEventTypeDeviceRecovered,
		RuleEventTypeDeviceAdded, RuleEventTypeDeviceChanged:
		return true
	}
	return false
}

// IsValidRuleScopeType reports whether t is a supported scope_type value.
func IsValidRuleScopeType(t string) bool {
	switch t {
	case RuleScopeAll, RuleScopeNetwork, RuleScopeDevice:
		return true
	}
	return false
}

// CreateRuleRequest is the body of POST /notification/rules.
type CreateRuleRequest struct {
	Name            string `json:"name"`
	EventType       string `json:"event_type"`
	ScopeType       string `json:"scope_type"`
	ScopeNetworkID  *int64 `json:"scope_network_id,omitempty"`
	ScopeDeviceUUID string `json:"scope_device_uuid,omitempty"`
	ChannelID       int64  `json:"channel_id"`
	CooldownMinutes int    `json:"cooldown_minutes"`
}

// UpdateRuleRequest is the body of PUT /notification/rules/{id}. All fields
// are required (full-replace, mirroring the channel PUT semantics).
type UpdateRuleRequest struct {
	Name            string `json:"name"`
	EventType       string `json:"event_type"`
	ScopeType       string `json:"scope_type"`
	ScopeNetworkID  *int64 `json:"scope_network_id,omitempty"`
	ScopeDeviceUUID string `json:"scope_device_uuid,omitempty"`
	ChannelID       int64  `json:"channel_id"`
	CooldownMinutes int    `json:"cooldown_minutes"`
}

// SetRuleEnabledRequest is the body of PATCH /notification/rules/{id}.
type SetRuleEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

// RuleResponse is the JSON shape returned by the rule endpoints.
type RuleResponse struct {
	ID              int64      `json:"id"`
	Name            string     `json:"name"`
	EventType       string     `json:"event_type"`
	ScopeType       string     `json:"scope_type"`
	ScopeNetworkID  *int64     `json:"scope_network_id,omitempty"`
	ScopeDeviceUUID string     `json:"scope_device_uuid,omitempty"`
	ChannelID       int64      `json:"channel_id"`
	CooldownMinutes int        `json:"cooldown_minutes"`
	Enabled         bool       `json:"enabled"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type RuleListResponse struct {
	Rules []RuleResponse `json:"rules"`
	Total int            `json:"total"`
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
