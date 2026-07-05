package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/notification"
)

// AlertEngine evaluates alert rules against device events and dispatches notifications.
type AlertEngine struct {
	store      RuleStore
	dispatcher *notification.Dispatcher
	logger     *slog.Logger
}

// NewAlertEngine creates a new AlertEngine.
func NewAlertEngine(store RuleStore, d *notification.Dispatcher) *AlertEngine {
	return &AlertEngine{
		store:      store,
		dispatcher: d,
		logger:     slog.Default(),
	}
}

// WithLogger sets a custom logger (for testing).
func (e *AlertEngine) WithLogger(logger *slog.Logger) *AlertEngine {
	e.logger = logger
	return e
}

// EvaluateDeviceStatus checks if any alert rules should fire based on a device status change.
// Called from heartbeat service when a device's status transitions.
func (e *AlertEngine) EvaluateDeviceStatus(ctx context.Context, deviceID int64, oldStatus, newStatus string) error {
	if oldStatus == newStatus {
		return nil // no actual transition
	}

	rules, err := e.store.ListEnabledAlertRules(ctx)
	if err != nil {
		e.logger.Error("alert: failed to list rules", "error", err)
		return err
	}

	now := time.Now()

	for _, rule := range rules {
		// Skip rules not applicable to this device
		if !e.ruleAppliesToDevice(rule, deviceID) {
			continue
		}

		// Check condition match
		if !e.matchesCondition(rule, deviceID, oldStatus, newStatus, nil, 0, 0) {
			continue
		}

		// Check cooldown
		if e.inCooldown(rule, now) {
			e.logger.Debug("alert: rule in cooldown", "rule_id", rule.ID, "cooldown_seconds", rule.CooldownSeconds)
			continue
		}

		// Match found — dispatch notification
		if !e.dispatchAlert(ctx, rule, deviceID, newStatus) {
			continue
		}

		// Update last_triggered_at
		e.updateLastTriggered(ctx, rule, now)
	}

	return nil
}

// EvaluateHeartbeatResult checks if heartbeat failure patterns trigger alerts.
func (e *AlertEngine) EvaluateHeartbeatResult(ctx context.Context, configID int64, result *db.HeartbeatResult, failCount int, timeoutCount int) error {
	rules, err := e.store.ListEnabledAlertRules(ctx)
	if err != nil {
		e.logger.Error("alert: failed to list rules for heartbeat", "error", err)
		return err
	}

	now := time.Now()

	for _, rule := range rules {
		// Skip rules not applicable to this device
		if !e.ruleAppliesToDevice(rule, result.DeviceID) {
			continue
		}

		// Only check heartbeat conditions
		ct := domain.ConditionType(rule.ConditionType)
		if ct != domain.ConditionHeartbeatFail && ct != domain.ConditionHeartbeatTimeout {
			continue
		}

		// Check condition match
		if !e.matchesCondition(rule, result.DeviceID, "", "", &result.Status, failCount, timeoutCount) {
			continue
		}

		// Check cooldown
		if e.inCooldown(rule, now) {
			e.logger.Debug("alert: heartbeat rule in cooldown", "rule_id", rule.ID)
			continue
		}

		// Match found — dispatch notification
		if !e.dispatchAlertForHeartbeat(ctx, rule, result.DeviceID, configID, result.Status) {
			continue
		}

		// Update last_triggered_at
		e.updateLastTriggered(ctx, rule, now)
	}

	return nil
}

// ruleAppliesToDevice returns true if the rule is global (device_id IS NULL) or targets this specific device.
func (e *AlertEngine) ruleAppliesToDevice(rule db.AlertRule, deviceID int64) bool {
	return rule.DeviceID == nil || *rule.DeviceID == deviceID
}

// matchesCondition checks if the rule's condition type matches the event.
func (e *AlertEngine) matchesCondition(rule db.AlertRule, deviceID int64, oldStatus, newStatus string, resultStatus *string, failCount, timeoutCount int) bool {
	ct := domain.ConditionType(rule.ConditionType)

	switch ct {
	case domain.ConditionDeviceOffline:
		return newStatus == "offline"

	case domain.ConditionHeartbeatFail:
		if resultStatus == nil || *resultStatus != "fail" {
			return false
		}
		return failCount >= int(rule.Threshold)

	case domain.ConditionHeartbeatTimeout:
		if resultStatus == nil || *resultStatus != "timeout" {
			return false
		}
		return timeoutCount >= int(rule.Threshold)

	default:
		return false
	}
}

// inCooldown checks if the rule's cooldown period has not elapsed since last trigger.
func (e *AlertEngine) inCooldown(rule db.AlertRule, now time.Time) bool {
	if rule.LastTriggeredAt == nil || rule.CooldownSeconds <= 0 {
		return false
	}
	elapsed := now.Sub(*rule.LastTriggeredAt)
	return elapsed < time.Duration(rule.CooldownSeconds)*time.Second
}

// dispatchAlert sends a notification via the dispatcher.
// Returns false if dispatch was skipped (channel not found/disabled).
func (e *AlertEngine) dispatchAlert(ctx context.Context, rule db.AlertRule, deviceID int64, status string) bool {
	channel, err := e.store.GetChannelByID(ctx, rule.ChannelID)
	if err != nil {
		e.logger.Error("alert: failed to get channel", "channel_id", rule.ChannelID, "error", err)
		return false
	}

	if channel.Enabled != 1 {
		e.logger.Debug("alert: channel disabled", "channel_id", rule.ChannelID)
		return false
	}

	metadata, _ := json.Marshal(map[string]interface{}{
		"device_id": deviceID,
		"condition": rule.ConditionType,
		"rule_id":   rule.ID,
		"status":    status,
	})

	ruleID := rule.ID
	e.dispatcher.Dispatch(ctx,
		domain.ChannelType(channel.Type),
		json.RawMessage(channel.Config),
		notification.NotificationPayload{
			Subject:  fmt.Sprintf("Alert: %s", rule.Name),
			Body:     fmt.Sprintf("Device %d status changed to '%s', triggering rule '%s'", deviceID, status, rule.Name),
			Metadata: metadata,
		},
		&ruleID,
		rule.ChannelID,
	)
	return true
}

// dispatchAlertForHeartbeat sends a notification for heartbeat failures.
// Returns false if dispatch was skipped.
func (e *AlertEngine) dispatchAlertForHeartbeat(ctx context.Context, rule db.AlertRule, deviceID, configID int64, resultStatus string) bool {
	channel, err := e.store.GetChannelByID(ctx, rule.ChannelID)
	if err != nil {
		e.logger.Error("alert: failed to get channel for heartbeat", "channel_id", rule.ChannelID, "error", err)
		return false
	}

	if channel.Enabled != 1 {
		e.logger.Debug("alert: channel disabled", "channel_id", rule.ChannelID)
		return false
	}

	metadata, _ := json.Marshal(map[string]interface{}{
		"device_id":     deviceID,
		"config_id":     configID,
		"condition":     rule.ConditionType,
		"rule_id":       rule.ID,
		"result_status": resultStatus,
	})

	ruleID := rule.ID
	e.dispatcher.Dispatch(ctx,
		domain.ChannelType(channel.Type),
		json.RawMessage(channel.Config),
		notification.NotificationPayload{
			Subject: fmt.Sprintf("Alert: %s", rule.Name),
			Body:    fmt.Sprintf("Device %d heartbeat %s (config %d), triggering rule '%s'", deviceID, resultStatus, configID, rule.Name),
			Metadata: metadata,
		},
		&ruleID,
		rule.ChannelID,
	)
	return true
}

// updateLastTriggered sets the last_triggered_at timestamp on a rule.
func (e *AlertEngine) updateLastTriggered(ctx context.Context, rule db.AlertRule, now time.Time) {
	_, err := e.store.UpdateAlertRule(ctx, db.UpdateAlertRuleParams{
		Name:            rule.Name,
		DeviceID:        rule.DeviceID,
		ConditionType:   rule.ConditionType,
		Threshold:       rule.Threshold,
		ChannelID:       rule.ChannelID,
		Enabled:         rule.Enabled,
		CooldownSeconds: rule.CooldownSeconds,
		LastTriggeredAt: &now,
		ID:              rule.ID,
	})
	if err != nil {
		e.logger.Error("alert: failed to update last_triggered_at", "rule_id", rule.ID, "error", err)
	}
}
