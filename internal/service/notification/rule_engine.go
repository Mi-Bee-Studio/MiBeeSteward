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
	"fmt"
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
// The engine is non-blocking: a slow downstream (dispatcher
// queue full, channel lookup error) logs + continues. The Watcher's push is
// non-blocking with a 64-deep buffer, so a slow engine will drop events;
// handleEvent must stay fast (no blocking HTTP; the dispatcher is async).
type RuleEngine struct {
	queries    *db.Queries
	watcher    *changedetect.Watcher
	dispatcher *Dispatcher
	logger     *slog.Logger

	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Per-(rule, device-mac) cooldown: the last time a rule fired for a device.
	// Keyed on MAC (not device_uuid or entity_id) because MAC is stable across
	// identity rescan/re-add, a device that is deleted then re-discovered gets
	// a fresh random uuid.NewString() and a new devices.id, but the same MAC.
	// In-memory only (lost on restart); the changedetect layer's own 15min
	// event-level cooldown is the backstop against duplicate dispatches.
	cooldownMu sync.Mutex
	lastSent   map[cooldownKey]time.Time
}

type cooldownKey struct {
	ruleID int64
	mac    string
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

// Start launches the subscriber goroutine. Calling twice is a no-op
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
	// do NOT drain the channel here, draining a closed-but-buffered channel can
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
// Device events and probe-target liveness events take separate paths (payload
// shape and scope semantics differ); other entity types are not rule-eligible.
func (e *RuleEngine) handleEvent(ctx context.Context, row db.ChangeLog) {
	switch row.EntityType {
	case changedetect.EntityTypeDevice:
		e.handleDeviceEvent(ctx, row)
	case changedetect.EntityTypeProbeTarget:
		e.handleProbeEvent(ctx, row)
	case changedetect.EntityTypeAgent:
		e.handleAgentEvent(ctx, row)
	}
}

// handleDeviceEvent is the historical rule path: device change events with
// device scope matching (all/network/device) and per-(rule,MAC) cooldown.
func (e *RuleEngine) handleDeviceEvent(ctx context.Context, row db.ChangeLog) {
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
		devMAC := ""
		if dev != nil {
			devMAC = dev.MacAddress
		}
		if !e.cooldownAllows(rule.ID, devMAC, rule.CooldownMinutes) {
			continue
		}
		e.dispatch(ctx, rule, row, dev)
		e.markFired(ctx, rule.ID, devMAC)
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
// anti-flap window. mac may be "" (unidentified device), in that case the
// cooldown is keyed on ruleID alone (all unidentified events share one bucket).
func (e *RuleEngine) cooldownAllows(ruleID int64, mac string, cooldownMinutes int64) bool {
	if cooldownMinutes <= 0 {
		return true
	}
	e.cooldownMu.Lock()
	defer e.cooldownMu.Unlock()
	last, ok := e.lastSent[cooldownKey{ruleID, mac}]
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
// last_triggered_at diagnostic column (errors logged, not fatal).
func (e *RuleEngine) markFired(ctx context.Context, ruleID int64, mac string) {
	e.cooldownMu.Lock()
	e.lastSent[cooldownKey{ruleID, mac}] = time.Now()
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
	case changedetect.ChangeTypeSpeaksWithNew:
		return "New device conversation"
	case changedetect.ChangeTypeListenPortAdded:
		return "New listening port"
	}
	return "Device event"
}

// agentSnap is the after_data snapshot the agentwatch sweeper stamps on its
// change_log rows (agent liveness). The snapshot is the identity source — it
// is seconds old at dispatch and survives agent deregistration.
type agentSnap struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
}

// handleAgentEvent matches agent fleet liveness transitions (agent_offline /
// agent_recovered). Like probe events, agent rules support scope=all only.
func (e *RuleEngine) handleAgentEvent(ctx context.Context, row db.ChangeLog) {
	rules, err := e.queries.ListEnabledRulesByEventType(ctx, row.ChangeType)
	if err != nil {
		e.logger.Error("notification rule engine: load rules failed", "event_type", row.ChangeType, "error", err)
		return
	}
	if len(rules) == 0 {
		return
	}

	snap := agentSnap{AgentID: "unknown-agent"}
	if row.AfterData != nil {
		var s agentSnap
		if err := json.Unmarshal([]byte(*row.AfterData), &s); err != nil || s.AgentID == "" {
			s = agentSnap{AgentID: "unknown-agent"}
		} else {
			snap = s
		}
	}
	if row.AgentID != nil && snap.AgentID == "unknown-agent" {
		snap.AgentID = *row.AgentID
	}

	entityKey := "agent:" + snap.AgentID
	for _, rule := range rules {
		if rule.ScopeType != domain.RuleScopeAll {
			continue
		}
		if !e.cooldownAllows(rule.ID, entityKey, rule.CooldownMinutes) {
			continue
		}
		e.dispatchAgent(ctx, rule, row, snap)
		e.markFired(ctx, rule.ID, entityKey)
	}
}

// dispatchAgent mirrors dispatch() for agent events: resolve the channel,
// build an agent-shaped payload, hand off to the Dispatcher.
func (e *RuleEngine) dispatchAgent(ctx context.Context, rule db.NotificationRule, row db.ChangeLog, snap agentSnap) {
	ch, err := e.queries.GetChannelByID(ctx, rule.ChannelID)
	if err != nil {
		e.logger.Error("notification rule engine: resolve channel failed", "rule_id", rule.ID, "channel_id", rule.ChannelID, "error", err)
		return
	}
	if ch.Enabled == 0 {
		return
	}
	payload := buildAgentPayload(rule, row, snap)
	ruleID := rule.ID
	e.dispatcher.Dispatch(ctx, domain.ChannelType(ch.Type), json.RawMessage(ch.Config), payload, &ruleID, ch.ID)
}

// buildAgentPayload constructs the agent-event payload. The display name is
// the hostname (the agent id is the stable identity and rides in source_ref).
func buildAgentPayload(rule db.NotificationRule, row db.ChangeLog, snap agentSnap) Payload {
	title := "Agent offline"
	if row.ChangeType == changedetect.ChangeTypeAgentRecovered {
		title = "Agent recovered"
	}
	name := snap.Hostname
	if name == "" {
		name = snap.AgentID
	}
	body := "Agent: " + snap.AgentID + "\n" +
		"Hostname: " + snap.Hostname + "\n" +
		"Version: " + snap.Version + "\n" +
		"Event: " + row.ChangeType + "\n" +
		"Detected at: " + row.DetectedAt.Format(time.RFC3339)

	meta := map[string]any{
		"event_type":  row.ChangeType,
		"agent_id":    snap.AgentID,
		"agent_name":  snap.Hostname,
		"rule_id":     rule.ID,
		"rule_name":   rule.Name,
		"detected_at": row.DetectedAt.Format(time.RFC3339),
		"source_ref":  "agent/" + snap.AgentID,
	}
	metaJSON, _ := json.Marshal(meta)
	return Payload{
		Subject:  title + ": " + name,
		Body:     body,
		Metadata: metaJSON,
	}
}

// probeSnap is the after_data snapshot the probe engine stamps on its
// change_log rows; the fallback identity source when the target row is gone.
type probeSnap struct {
	TargetName string `json:"target_name"`
	Module     string `json:"module"`
	Target     string `json:"target"`
	Vantage    string `json:"vantage"`
	Error      string `json:"error"`
}

// handleProbeEvent matches probe-target liveness transitions (probe_failed /
// probe_recovered). Probe rules only support scope=all: a probe target probes
// an arbitrary endpoint and is not network-scoped, and even a device-bound
// target's verdict concerns the endpoint, not the asset row.
func (e *RuleEngine) handleProbeEvent(ctx context.Context, row db.ChangeLog) {
	rules, err := e.queries.ListEnabledRulesByEventType(ctx, row.ChangeType)
	if err != nil {
		e.logger.Error("notification rule engine: load rules failed", "event_type", row.ChangeType, "error", err)
		return
	}
	if len(rules) == 0 {
		return
	}

	snap := e.probeEventTarget(ctx, row)
	entityKey := "probe"
	if row.EntityID != nil && *row.EntityID > 0 {
		entityKey = fmt.Sprintf("probe:%d", *row.EntityID)
	}

	for _, rule := range rules {
		if rule.ScopeType != domain.RuleScopeAll {
			continue
		}
		if !e.cooldownAllows(rule.ID, entityKey, rule.CooldownMinutes) {
			continue
		}
		e.dispatchProbe(ctx, rule, row, snap)
		e.markFired(ctx, rule.ID, entityKey)
	}
}

// probeEventTarget resolves the target's display identity. The recorder's
// after_data snapshot is the base (it carries the run's error text); the live
// row then overrides name/module/address when it still exists (survives
// renames) — a target deleted between emission and dispatch keeps the
// snapshot identity.
func (e *RuleEngine) probeEventTarget(ctx context.Context, row db.ChangeLog) probeSnap {
	snap := probeSnap{TargetName: "unknown target"}
	if row.AfterData != nil {
		var s probeSnap
		if err := json.Unmarshal([]byte(*row.AfterData), &s); err != nil || s.TargetName == "" {
			s = probeSnap{TargetName: "unknown target"}
		} else {
			snap = s
		}
	}
	if row.EntityID != nil && *row.EntityID > 0 {
		if t, err := e.queries.GetProbeTarget(ctx, *row.EntityID); err == nil {
			snap.TargetName, snap.Module, snap.Target = t.Name, t.Module, t.Target
		} else if !errors.Is(err, sql.ErrNoRows) {
			e.logger.Error("notification rule engine: resolve probe target failed", "entity_id", *row.EntityID, "error", err)
		}
	}
	return snap
}

// dispatchProbe mirrors dispatch() for probe events: resolve the channel,
// build a probe-shaped payload, hand off to the Dispatcher.
func (e *RuleEngine) dispatchProbe(ctx context.Context, rule db.NotificationRule, row db.ChangeLog, snap probeSnap) {
	ch, err := e.queries.GetChannelByID(ctx, rule.ChannelID)
	if err != nil {
		e.logger.Error("notification rule engine: resolve channel failed", "rule_id", rule.ID, "channel_id", rule.ChannelID, "error", err)
		return
	}
	if ch.Enabled == 0 {
		return
	}
	payload := buildProbePayload(rule, row, snap)
	ruleID := rule.ID
	e.dispatcher.Dispatch(ctx, domain.ChannelType(ch.Type), json.RawMessage(ch.Config), payload, &ruleID, ch.ID)
}

// buildProbePayload constructs the probe-event payload. Metadata carries a
// stable source_ref (probe/<target_id>) so the alert-envelope dedup key pairs
// probe_failed/probe_recovered per target across renames.
func buildProbePayload(rule db.NotificationRule, row db.ChangeLog, snap probeSnap) Payload {
	title := "Probe failed"
	if row.ChangeType == changedetect.ChangeTypeProbeRecovered {
		title = "Probe recovered"
	}
	body := "Target: " + snap.TargetName + "\n" +
		"Module: " + snap.Module + "\n" +
		"Address: " + snap.Target + "\n" +
		"Vantage: " + snap.Vantage + "\n" +
		"Event: " + row.ChangeType + "\n"
	if snap.Error != "" {
		body += "Error: " + snap.Error + "\n"
	}
	body += "Detected at: " + row.DetectedAt.Format(time.RFC3339)

	meta := map[string]any{
		"event_type":     row.ChangeType,
		"target_name":    snap.TargetName,
		"module":         snap.Module,
		"target_address": snap.Target,
		"rule_id":        rule.ID,
		"rule_name":      rule.Name,
		"detected_at":    row.DetectedAt.Format(time.RFC3339),
	}
	if snap.Vantage != "" {
		meta["vantage"] = snap.Vantage
	}
	if snap.Error != "" {
		meta["error"] = snap.Error
	}
	if row.EntityID != nil && *row.EntityID > 0 {
		meta["target_id"] = *row.EntityID
		meta["source_ref"] = fmt.Sprintf("probe/%d", *row.EntityID)
	}
	metaJSON, _ := json.Marshal(meta)
	return Payload{
		Subject:  title + ": " + snap.TargetName,
		Body:     body,
		Metadata: metaJSON,
	}
}
