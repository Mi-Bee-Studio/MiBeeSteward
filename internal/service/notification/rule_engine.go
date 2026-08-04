// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. A commercial license is available for use cases
// the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package notification

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"log/slog"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// RuleEngine subscribes to changedetect.Watcher and dispatches matching
// notification rules via the existing Dispatcher (#139).
//
// Flow:
//
//	changedetect.Watcher → db.ChangeLog row
//	  → ListEnabledRulesByEventType(change_type)
//	    → per-rule: scope filter (all/network/device) + per-(rule,device) cooldown
//	      → resolve channel (GetChannelByID) + device name (GetDevice)
//	        → Dispatcher.Dispatch(...)
//
// The engine is best-effort and non-blocking: a slow downstream (dispatcher
// queue full, channel lookup error) logs + continues. The Watcher's push is
// non-blocking with a 64-deep buffer, so a slow engine will drop events —
// handleEvent must stay fast (no blocking HTTP; the dispatcher is async).
type RuleEngine struct {
	queries    *db.Queries
	watcher    *changedetect.Watcher
	dispatcher *Dispatcher
	logger     *slog.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Per-(rule, device-uuid) cooldown: the last time a rule fired for a device.
	// In-memory only (lost on restart); the changedetect layer's own 15min
	// event-level cooldown is the backstop against duplicate dispatches.
	cooldownMu sync.Mutex
	lastSent   map[cooldownKey]time.Time
}

type cooldownKey struct {
	ruleID int64
	uuid   string
}

// NewRuleEngine constructs a RuleEngine. watcher/dispatcher may outlive the
// engine (they're shared singletons); the engine only adds a subscriber.
func NewRuleEngine(queries *db.Queries, watcher *changedetect.Watcher, dispatcher *Dispatcher, logger *slog.Logger) *RuleEngine {
	if logger == nil {
		logger = slog.Default()
	}
	return &RuleEngine{
		queries:    queries,
		watcher:    watcher,
		dispatcher: dispatcher,
		logger:     logger,
		lastSent:   make(map[cooldownKey]time.Time),
	}
}

// Start launches the subscriber goroutine. Idempotent; calling twice is a no-op
// on the second call. The goroutine exits when Stop is called or ctx is cancelled.
func (e *RuleEngine) Start(ctx context.Context) {
	if e.watcher == nil || e.dispatcher == nil {
		e.logger.Warn("notification rule engine disabled: watcher or dispatcher is nil")
		return
	}
	subCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	e.wg.Add(1)
	go e.run(subCtx)
	e.logger.Info("notification rule engine started")
}

// Stop unsubscribes from the Watcher and waits for the goroutine to exit.
func (e *RuleEngine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
}

func (e *RuleEngine) run(ctx context.Context) {
	defer e.wg.Done()
	sub := e.watcher.Subscribe()
	// Unsubscribe on exit so the Watcher stops holding a reference to this
	// channel (Unsubscribe closes it). Unlike the /changes/watch SSE handler we
	// do NOT drain the channel here — draining a closed-but-buffered channel can
	// race with concurrent push and is unnecessary when Stop() waits on the wg.
	defer e.watcher.Unsubscribe(sub)
	for {
		select {
		case <-ctx.Done():
			return
		case row, ok := <-sub:
			if !ok {
				return
			}
			e.handleEvent(ctx, row)
		}
	}
}

// handleEvent matches one change_log row against enabled rules and dispatches.
func (e *RuleEngine) handleEvent(ctx context.Context, row db.ChangeLog) {
	// Only device events are rule-eligible (entity_type guards against future
	// non-device change types like service/topology_edge).
	if row.EntityType != changedetect.EntityTypeDevice {
		return
	}
	rules, err := e.queries.ListEnabledRulesByEventType(ctx, row.ChangeType)
	if err != nil {
		e.logger.Error("notification rule engine: load rules failed", "event_type", row.ChangeType, "error", err)
		return
	}
	if len(rules) == 0 {
		return
	}

	// Resolve the device once (name/ip/mac/uuid) for payload + device-scope match.
	// entity_id may be nil for unidentified neighbors; skip device-scope rules.
	var dev *db.Device
	if row.EntityID != nil && *row.EntityID > 0 {
		d, err := e.queries.GetDevice(ctx, *row.EntityID)
		if err == nil {
			dev = &d
		} else if !errors.Is(err, sql.ErrNoRows) {
			e.logger.Error("notification rule engine: resolve device failed", "entity_id", *row.EntityID, "error", err)
		}
	}

	for _, rule := range rules {
		if !e.scopeMatches(rule, row, dev) {
			continue
		}
		devUUID := ""
		if dev != nil {
			devUUID = dev.DeviceUuid
		}
		if !e.cooldownAllows(rule.ID, devUUID, rule.CooldownMinutes) {
			continue
		}
		e.dispatch(ctx, rule, row, dev)
		e.markFired(ctx, rule.ID, devUUID)
	}
}

// scopeMatches applies the rule's scope_type filter.
func (e *RuleEngine) scopeMatches(rule db.NotificationRule, row db.ChangeLog, dev *db.Device) bool {
	switch rule.ScopeType {
	case domain.RuleScopeAll:
		return true
	case domain.RuleScopeNetwork:
		// row.NetworkID is the network the change was observed on.
		if rule.ScopeNetworkID == nil || row.NetworkID == nil {
			return rule.ScopeNetworkID == nil && row.NetworkID == nil
		}
		return *rule.ScopeNetworkID == *row.NetworkID
	case domain.RuleScopeDevice:
		// Match by device_uuid (stable across IP changes/rescans). The device
		// must have been resolved (dev != nil); unidentified neighbors never
		// match a device-scoped rule.
		if dev == nil || rule.ScopeDeviceUuid == "" {
			return false
		}
		return dev.DeviceUuid == rule.ScopeDeviceUuid
	}
	return false
}

// cooldownAllows reports whether the (rule, device) pair is outside its
// anti-flap window. uuid may be "" (unidentified device) — in that case the
// cooldown is keyed on ruleID alone.
func (e *RuleEngine) cooldownAllows(ruleID int64, uuid string, cooldownMinutes int64) bool {
	if cooldownMinutes <= 0 {
		return true
	}
	e.cooldownMu.Lock()
	defer e.cooldownMu.Unlock()
	last, ok := e.lastSent[cooldownKey{ruleID, uuid}]
	if !ok {
		return true
	}
	return time.Since(last) >= time.Duration(cooldownMinutes)*time.Minute
}

// dispatch resolves the channel, builds a payload, and hands off to the
// existing Dispatcher. Channel lookup errors are logged + skipped (a deleted
// channel with CASCADE should have removed the rule, but defend in depth).
func (e *RuleEngine) dispatch(ctx context.Context, rule db.NotificationRule, row db.ChangeLog, dev *db.Device) {
	ch, err := e.queries.GetChannelByID(ctx, rule.ChannelID)
	if err != nil {
		e.logger.Error("notification rule engine: resolve channel failed", "rule_id", rule.ID, "channel_id", rule.ChannelID, "error", err)
		return
	}
	if ch.Enabled == 0 {
		return // skip disabled channels silently
	}
	payload := buildPayload(rule, row, dev)
	ruleID := rule.ID
	e.dispatcher.Dispatch(ctx, domain.ChannelType(ch.Type), json.RawMessage(ch.Config), payload, &ruleID, ch.ID)
}

// markFired records the cooldown timestamp (in-memory) + bumps the rule's
// last_triggered_at diagnostic column (best-effort, errors logged not fatal).
func (e *RuleEngine) markFired(ctx context.Context, ruleID int64, uuid string) {
	e.cooldownMu.Lock()
	e.lastSent[cooldownKey{ruleID, uuid}] = time.Now()
	e.cooldownMu.Unlock()
	if err := e.queries.MarkNotificationRuleTriggered(ctx, ruleID); err != nil {
		e.logger.Debug("notification rule engine: mark triggered failed", "rule_id", ruleID, "error", err)
	}
}

// buildPayload constructs the webhook/email payload. Subject + Body are
// English (server has no locale context); Metadata carries structured fields
// so a webhook receiver can localize/render as needed.
func buildPayload(rule db.NotificationRule, row db.ChangeLog, dev *db.Device) Payload {
	devName, devIP, devMAC, devType := "unknown device", "", "", ""
	if dev != nil {
		devName = dev.Name
		if devName == "" {
			devName = dev.IpAddress
		}
		devIP = dev.IpAddress
		devMAC = dev.MacAddress
		devType = dev.Type
	}
	subject := eventTitle(row.ChangeType) + ": " + devName
	body := "Device: " + devName + "\n" +
		"IP: " + devIP + "\n" +
		"MAC: " + devMAC + "\n" +
		"Type: " + devType + "\n" +
		"Event: " + row.ChangeType + "\n" +
		"Detected at: " + row.DetectedAt.Format(time.RFC3339)
	meta := map[string]any{
		"event_type":  row.ChangeType,
		"device_name": devName,
		"ip_address":  devIP,
		"mac_address": devMAC,
		"device_type": devType,
		"rule_id":     rule.ID,
		"rule_name":   rule.Name,
		"detected_at": row.DetectedAt.Format(time.RFC3339),
	}
	if row.NetworkID != nil {
		meta["network_id"] = *row.NetworkID
	}
	metaJSON, _ := json.Marshal(meta)
	return Payload{
		Subject:  subject,
		Body:     body,
		Metadata: metaJSON,
	}
}

// eventTitle maps a change_type to a human-readable English title.
func eventTitle(changeType string) string {
	switch changeType {
	case changedetect.ChangeTypeDeviceLost:
		return "Device lost"
	case changedetect.ChangeTypeDeviceRecovered:
		return "Device recovered"
	case changedetect.ChangeTypeDeviceAdded:
		return "Device added"
	case changedetect.ChangeTypeDeviceChanged:
		return "Device changed"
	}
	return "Device event"
}
