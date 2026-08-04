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
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// recordingLogCreator records CreateNotificationLog calls (the Dispatcher writes
// one row per dispatch attempt). Inspecting its logs is how the test asserts
// which rule/channel/payload the engine dispatched.
type recordingLogCreator struct {
	mu   sync.Mutex
	logs []db.CreateNotificationLogParams
}

func (r *recordingLogCreator) CreateNotificationLog(_ context.Context, arg db.CreateNotificationLogParams) (db.NotificationLog, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, arg)
	return db.NotificationLog{ID: int64(len(r.logs))}, nil
}

func (r *recordingLogCreator) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.logs)
}

// recordingSender is a Sender that records every payload it "sent".
type recordingSender struct {
	mu    sync.Mutex
	sents []Payload
}

func (s *recordingSender) Send(_ context.Context, payload Payload) SendResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sents = append(s.sents, payload)
	return SendResult{Success: true}
}

func (s *recordingSender) snapshot() []Payload {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]Payload, len(s.sents))
	copy(cp, s.sents)
	return cp
}

// setupTestEngine builds an in-memory SQLite with the schema, a real Dispatcher
// wired to a recording log + recording sender, and a RuleEngine. The engine's
// goroutine is NOT started — tests call handleEvent directly for determinism.
// Returns the engine, queries, recorder, and sender.
func setupTestEngine(t *testing.T) (e *RuleEngine, q *db.Queries, log *recordingLogCreator, sender *recordingSender) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	q = db.New(conn)

	log = &recordingLogCreator{}
	sender = &recordingSender{}
	d := NewDispatcher(log, nil).
		WithSenderFactory(func(_ domain.ChannelType, _ json.RawMessage) (Sender, error) {
			return sender, nil
		})
	d.Start(context.Background())
	t.Cleanup(d.Stop)

	// watcher is nil — we never call Start(); tests invoke handleEvent directly.
	e = NewRuleEngine(q, nil, d, nil)
	return e, q, log, sender
}

// drain waits for the dispatcher's async workers to finish any pending jobs,
// then returns. handleEvent calls Dispatch (non-blocking, queues a job); this
// polls the recorder/sender until wantCount is reached or the deadline.
func drain(t *testing.T, log *recordingLogCreator, wantCount int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if log.count() >= wantCount {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func seedChannel(t *testing.T, q *db.Queries, name string, enabled bool) int64 {
	t.Helper()
	en := int64(0)
	if enabled {
		en = 1
	}
	ch, err := q.CreateChannel(context.Background(), db.CreateChannelParams{
		Name: name, Type: "webhook", Config: `{"url":"http://test"}`, Enabled: en,
	})
	require.NoError(t, err)
	return ch.ID
}

func seedRule(t *testing.T, q *db.Queries, name, eventType, scopeType string, channelID int64, enabled bool, extra ...int64) int64 {
	t.Helper()
	cooldown := int64(30)
	if len(extra) > 0 {
		cooldown = extra[0]
	}
	en := int64(0)
	if enabled {
		en = 1
	}
	var netID *int64
	rule, err := q.CreateNotificationRule(context.Background(), db.CreateNotificationRuleParams{
		Name: name, EventType: eventType, ScopeType: scopeType,
		ScopeNetworkID: netID, ScopeDeviceUuid: "", ChannelID: channelID,
		CooldownMinutes: cooldown, Enabled: en,
	})
	require.NoError(t, err)
	return rule.ID
}

func seedDevice(t *testing.T, q *db.Queries, name, ip, uuid string) int64 {
	t.Helper()
	dev, err := q.CreateDevice(context.Background(), db.CreateDeviceParams{
		DeviceUuid: uuid, Name: name, Type: "camera", IpAddress: ip, Status: "online",
		MacAddress:     "aa:bb:cc:00:00:01", // stable MAC — cooldown keys on this
		UserAttributes: "{}",                // CHECK(json_valid(user_attributes)) requires valid JSON
	})
	require.NoError(t, err)
	return dev.ID
}

// TestRuleEngine_EventTypeMatch: a device_lost rule fires on lost, NOT on added.
func TestRuleEngine_EventTypeMatch(t *testing.T) {
	e, q, log, _ := setupTestEngine(t)
	chID := seedChannel(t, q, "wh", true)
	lostRule := seedRule(t, q, "lost-rule", "device_lost", "all", chID, true)
	addedRule := seedRule(t, q, "added-rule", "device_added", "all", chID, true)
	devID := seedDevice(t, q, "cam1", "10.0.0.5", "uuid-cam1")

	// lost event → only lost-rule fires (1 dispatch).
	e.handleEvent(context.Background(), db.ChangeLog{
		ChangeType: "device_lost", EntityType: "device", EntityID: &devID, DetectedAt: time.Now(),
	})
	drain(t, log, 1)
	require.Equal(t, 1, log.count())
	assert.Equal(t, lostRule, *log.logs[0].RuleID)

	// added event → only added-rule fires (total 2).
	start := log.count()
	e.handleEvent(context.Background(), db.ChangeLog{
		ChangeType: "device_added", EntityType: "device", EntityID: &devID, DetectedAt: time.Now(),
	})
	drain(t, log, start+1)
	require.Equal(t, 2, log.count())
	assert.Equal(t, addedRule, *log.logs[1].RuleID)
}

// TestRuleEngine_DisabledRuleSkipped: a disabled rule never dispatches.
func TestRuleEngine_DisabledRuleSkipped(t *testing.T) {
	e, q, log, _ := setupTestEngine(t)
	chID := seedChannel(t, q, "wh", true)
	seedRule(t, q, "off-rule", "device_added", "all", chID, false)
	devID := seedDevice(t, q, "dev", "10.0.0.6", "uuid-dev")

	e.handleEvent(context.Background(), db.ChangeLog{
		ChangeType: "device_added", EntityType: "device", EntityID: &devID, DetectedAt: time.Now(),
	})
	drain(t, log, 1)
	assert.Equal(t, 0, log.count(), "disabled rule must not dispatch")
}

// TestRuleEngine_DisabledChannelSkipped: a rule pointing at a disabled channel
// does not dispatch.
func TestRuleEngine_DisabledChannelSkipped(t *testing.T) {
	e, q, log, _ := setupTestEngine(t)
	chID := seedChannel(t, q, "off-wh", false)
	seedRule(t, q, "rule", "device_added", "all", chID, true)
	devID := seedDevice(t, q, "dev", "10.0.0.7", "uuid-dev")

	e.handleEvent(context.Background(), db.ChangeLog{
		ChangeType: "device_added", EntityType: "device", EntityID: &devID, DetectedAt: time.Now(),
	})
	drain(t, log, 1)
	assert.Equal(t, 0, log.count(), "rule with disabled channel must not dispatch")
}

// TestRuleEngine_Cooldown: a second event for the same (rule,device) within the
// cooldown window is suppressed.
func TestRuleEngine_Cooldown(t *testing.T) {
	e, q, log, _ := setupTestEngine(t)
	chID := seedChannel(t, q, "wh", true)
	// 60-minute cooldown.
	seedRule(t, q, "cool", "device_added", "all", chID, true, 60)
	devID := seedDevice(t, q, "dev", "10.0.0.8", "uuid-dev")

	// First event fires.
	e.handleEvent(context.Background(), db.ChangeLog{
		ChangeType: "device_added", EntityType: "device", EntityID: &devID, DetectedAt: time.Now(),
	})
	drain(t, log, 1)
	require.Equal(t, 1, log.count())

	// Second event (same device, within 60min) suppressed.
	e.handleEvent(context.Background(), db.ChangeLog{
		ChangeType: "device_added", EntityType: "device", EntityID: &devID, DetectedAt: time.Now(),
	})
	drain(t, log, 2)
	assert.Equal(t, 1, log.count(), "cooldown should suppress the duplicate dispatch")
}

// TestRuleEngine_PayloadShape: the dispatched payload carries device name + IP +
// structured metadata.
func TestRuleEngine_PayloadShape(t *testing.T) {
	e, q, _, sender := setupTestEngine(t)
	chID := seedChannel(t, q, "wh", true)
	seedRule(t, q, "shape", "device_lost", "all", chID, true)
	devID := seedDevice(t, q, "MyCamera", "10.0.0.9", "uuid-cam")

	e.handleEvent(context.Background(), db.ChangeLog{
		ChangeType: "device_lost", EntityType: "device", EntityID: &devID, DetectedAt: time.Now(),
	})

	// Wait for the sender to record the payload.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(sender.snapshot()) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	sents := sender.snapshot()
	require.Len(t, sents, 1)
	assert.Contains(t, sents[0].Subject, "MyCamera")
	assert.Contains(t, sents[0].Body, "10.0.0.9")
	var meta map[string]any
	require.NoError(t, json.Unmarshal(sents[0].Metadata, &meta))
	assert.Equal(t, "device_lost", meta["event_type"])
	assert.Equal(t, "MyCamera", meta["device_name"])
}

// TestRuleEngine_NonDeviceEventIgnored: a non-device entity_type (e.g. service)
// is ignored even if a rule matches its change_type string.
func TestRuleEngine_NonDeviceEventIgnored(t *testing.T) {
	e, q, log, _ := setupTestEngine(t)
	chID := seedChannel(t, q, "wh", true)
	seedRule(t, q, "rule", "device_added", "all", chID, true)
	devID := seedDevice(t, q, "dev", "10.0.0.10", "uuid-dev")

	// entity_type="service" → engine returns early (no dispatch).
	e.handleEvent(context.Background(), db.ChangeLog{
		ChangeType: "device_added", EntityType: "service", EntityID: &devID, DetectedAt: time.Now(),
	})
	drain(t, log, 1)
	assert.Equal(t, 0, log.count(), "non-device events must be ignored")
}
