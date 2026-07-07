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
}

type ChannelListResponse struct {
	Channels []ChannelResponse `json:"channels"`
	Total    int               `json:"total"`
}

type NotificationLogListResponse struct {
	Logs  []NotificationLogResponse `json:"logs"`
	Total int                       `json:"total"`
}
