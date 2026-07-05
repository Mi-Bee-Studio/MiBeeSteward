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

// ConditionType represents the condition that triggers an alert.
type ConditionType string

const (
	ConditionDeviceOffline    ConditionType = "device_offline"
	ConditionHeartbeatFail    ConditionType = "heartbeat_fail"
	ConditionHeartbeatTimeout ConditionType = "heartbeat_timeout"
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

type CreateAlertRuleRequest struct {
	Name            string        `json:"name"`
	DeviceID        *int64        `json:"device_id,omitempty"`
	ConditionType   ConditionType `json:"condition_type"`
	Threshold       int64         `json:"threshold"`
	ChannelID       int64         `json:"channel_id"`
	Enabled         *bool         `json:"enabled,omitempty"`
	CooldownSeconds int64         `json:"cooldown_seconds"`
}

type UpdateAlertRuleRequest struct {
	Name            *string        `json:"name,omitempty"`
	DeviceID        *int64         `json:"device_id,omitempty"`
	ConditionType   *ConditionType `json:"condition_type,omitempty"`
	Threshold       *int64         `json:"threshold,omitempty"`
	ChannelID       *int64         `json:"channel_id,omitempty"`
	Enabled         *bool          `json:"enabled,omitempty"`
	CooldownSeconds *int64         `json:"cooldown_seconds,omitempty"`
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

type AlertRuleResponse struct {
	ID              int64      `json:"id"`
	Name            string     `json:"name"`
	DeviceID        *int64     `json:"device_id,omitempty"`
	ConditionType   string     `json:"condition_type"`
	Threshold       int64      `json:"threshold"`
	ChannelID       int64      `json:"channel_id"`
	Enabled         bool       `json:"enabled"`
	CooldownSeconds int64      `json:"cooldown_seconds"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type NotificationLogResponse struct {
	ID           int64     `json:"id"`
	RuleID       *int64    `json:"rule_id,omitempty"`
	ChannelID    *int64    `json:"channel_id,omitempty"`
	Status       string    `json:"status"`
	Payload      string    `json:"payload"`
	ErrorMessage string    `json:"error_message"`
	SentAt       time.Time `json:"sent_at"`
}

type ChannelListResponse struct {
	Channels []ChannelResponse `json:"channels"`
	Total    int               `json:"total"`
}

type AlertRuleListResponse struct {
	Rules []AlertRuleResponse `json:"rules"`
	Total int                 `json:"total"`
}

type NotificationLogListResponse struct {
	Logs  []NotificationLogResponse `json:"logs"`
	Total int                       `json:"total"`
}
