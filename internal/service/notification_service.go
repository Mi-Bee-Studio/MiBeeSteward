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
	ErrChannelNotFound   = errors.New("notification channel not found")
	ErrAlertRuleNotFound = errors.New("alert rule not found")
)

// NotificationService handles notification channel, alert rule, and log business logic.
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

// --- Alert Rule CRUD ---

// CreateAlertRule validates and creates a new alert rule.
func (s *NotificationService) CreateAlertRule(ctx context.Context, req domain.CreateAlertRuleRequest) (*domain.AlertRuleResponse, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("rule name is required")
	}
	if req.ChannelID <= 0 {
		return nil, fmt.Errorf("valid channel ID is required")
	}
	if req.CooldownSeconds <= 0 {
		return nil, fmt.Errorf("cooldown seconds must be positive")
	}

	enabled := int64(1)
	if req.Enabled != nil && !*req.Enabled {
		enabled = 0
	}

	rule, err := s.q.CreateAlertRule(ctx, db.CreateAlertRuleParams{
		Name:            req.Name,
		DeviceID:        req.DeviceID,
		ConditionType:   string(req.ConditionType),
		Threshold:       req.Threshold,
		ChannelID:       req.ChannelID,
		Enabled:         enabled,
		CooldownSeconds: req.CooldownSeconds,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create alert rule: %w", err)
	}

	resp := toAlertRuleResponse(rule)
	return &resp, nil
}

// GetAlertRule retrieves an alert rule by ID.
func (s *NotificationService) GetAlertRule(ctx context.Context, id int64) (*domain.AlertRuleResponse, error) {
	rule, err := s.q.GetAlertRuleByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAlertRuleNotFound
		}
		return nil, fmt.Errorf("failed to get alert rule: %w", err)
	}

	resp := toAlertRuleResponse(rule)
	return &resp, nil
}

// ListAlertRules returns all alert rules.
func (s *NotificationService) ListAlertRules(ctx context.Context) ([]domain.AlertRuleResponse, error) {
	rules, err := s.q.ListAlertRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list alert rules: %w", err)
	}

	result := make([]domain.AlertRuleResponse, len(rules))
	for i, rule := range rules {
		result[i] = toAlertRuleResponse(rule)
	}
	return result, nil
}

// UpdateAlertRule updates an existing alert rule. Preserves existing values for unset fields.
func (s *NotificationService) UpdateAlertRule(ctx context.Context, id int64, req domain.UpdateAlertRuleRequest) (*domain.AlertRuleResponse, error) {
	existing, err := s.q.GetAlertRuleByID(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAlertRuleNotFound
		}
		return nil, fmt.Errorf("failed to get alert rule: %w", err)
	}

	name := existing.Name
	if req.Name != nil {
		name = *req.Name
	}

	deviceID := existing.DeviceID
	if req.DeviceID != nil {
		deviceID = req.DeviceID
	}

	conditionType := existing.ConditionType
	if req.ConditionType != nil {
		conditionType = string(*req.ConditionType)
	}

	threshold := existing.Threshold
	if req.Threshold != nil {
		threshold = *req.Threshold
	}

	channelID := existing.ChannelID
	if req.ChannelID != nil {
		channelID = *req.ChannelID
	}

	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = int64(0)
		if *req.Enabled {
			enabled = 1
		}
	}

	cooldownSeconds := existing.CooldownSeconds
	if req.CooldownSeconds != nil {
		cooldownSeconds = *req.CooldownSeconds
	}

	rule, err := s.q.UpdateAlertRule(ctx, db.UpdateAlertRuleParams{
		Name:            name,
		DeviceID:        deviceID,
		ConditionType:   conditionType,
		Threshold:       threshold,
		ChannelID:       channelID,
		Enabled:         enabled,
		CooldownSeconds: cooldownSeconds,
		LastTriggeredAt: existing.LastTriggeredAt,
		ID:              id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update alert rule: %w", err)
	}

	resp := toAlertRuleResponse(rule)
	return &resp, nil
}

// DeleteAlertRule deletes an alert rule by ID.
func (s *NotificationService) DeleteAlertRule(ctx context.Context, id int64) error {
	err := s.q.DeleteAlertRule(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete alert rule: %w", err)
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

func toAlertRuleResponse(rule db.AlertRule) domain.AlertRuleResponse {
	return domain.AlertRuleResponse{
		ID:              rule.ID,
		Name:            rule.Name,
		DeviceID:        rule.DeviceID,
		ConditionType:   rule.ConditionType,
		Threshold:       rule.Threshold,
		ChannelID:       rule.ChannelID,
		Enabled:         rule.Enabled == 1,
		CooldownSeconds: rule.CooldownSeconds,
		LastTriggeredAt: rule.LastTriggeredAt,
		CreatedAt:       rule.CreatedAt,
		UpdatedAt:       rule.UpdatedAt,
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
