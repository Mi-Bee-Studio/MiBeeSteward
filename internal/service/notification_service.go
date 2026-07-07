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
		result[i] = toNotificationLogResponse(log)
	}
	return result, total, nil
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

func toNotificationLogResponse(log db.NotificationLog) domain.NotificationLogResponse {
	return domain.NotificationLogResponse{
		ID:           log.ID,
		RuleID:       log.RuleID,
		ChannelID:    log.ChannelID,
		Status:       log.Status,
		Payload:      log.Payload,
		ErrorMessage: log.ErrorMessage,
		SentAt:       log.SentAt,
	}
}
