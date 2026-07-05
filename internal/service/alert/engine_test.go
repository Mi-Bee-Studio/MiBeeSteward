package alert

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/notification"
)

// --- Mocks ---

// mockRuleStore implements RuleStore + notification.LogCreator.
type mockRuleStore struct {
	rules    []db.AlertRule
	channels map[int64]db.NotificationChannel
	updated  atomic.Int32 // count of UpdateAlertRule calls
	logs     atomic.Int32 // count of CreateNotificationLog calls
}

func (m *mockRuleStore) ListEnabledAlertRules(_ context.Context) ([]db.AlertRule, error) {
	return m.rules, nil
}

func (m *mockRuleStore) GetChannelByID(_ context.Context, id int64) (db.NotificationChannel, error) {
	ch, ok := m.channels[id]
	if !ok {
		return db.NotificationChannel{}, nil // treat as empty — engine logs error and skips
	}
	return ch, nil
}

func (m *mockRuleStore) UpdateAlertRule(_ context.Context, arg db.UpdateAlertRuleParams) (db.AlertRule, error) {
	m.updated.Add(1)
	return db.AlertRule{ID: arg.ID}, nil
}

// CreateNotificationLog implements notification.LogCreator for the dispatcher.
func (m *mockRuleStore) CreateNotificationLog(_ context.Context, _ db.CreateNotificationLogParams) (db.NotificationLog, error) {
	m.logs.Add(1)
	return db.NotificationLog{ID: 1}, nil
}

func (m *mockRuleStore) updateCount() int { return int(m.updated.Load()) }
func (m *mockRuleStore) logCount() int    { return int(m.logs.Load()) }

// testSenderFunc implements notification.Sender.
type testSenderFunc func(ctx context.Context, payload notification.Payload) notification.SendResult

func (f testSenderFunc) Send(ctx context.Context, payload notification.Payload) notification.SendResult {
	return f(ctx, payload)
}

// newEngineWithRealDispatcher creates a real dispatcher with a fast mock sender.
func newEngineWithRealDispatcher(store *mockRuleStore) (*Engine, *notification.Dispatcher) {
	realDisp := notification.NewDispatcher(store, slog.Default())
	realDisp.WithSenderFactory(func(_ domain.ChannelType, _ json.RawMessage) (notification.Sender, error) {
		return testSenderFunc(func(_ context.Context, _ notification.Payload) notification.SendResult {
			return notification.SendResult{Success: true}
		}), nil
	})

	ctx := context.Background()
	realDisp.Start(ctx)

	e := NewEngine(store, realDisp)
	e.WithLogger(slog.Default())

	return e, realDisp
}

// --- Fixtures ---

func globalOfflineRule(id int64, channelID int64, cooldown int64) db.AlertRule {
	return db.AlertRule{
		ID:              id,
		Name:            "Global Device Offline",
		DeviceID:        nil,
		ConditionType:   string(domain.ConditionDeviceOffline),
		Threshold:       1,
		ChannelID:       channelID,
		Enabled:         1,
		CooldownSeconds: cooldown,
	}
}

func deviceOfflineRule(id int64, deviceID int64, channelID int64, cooldown int64) db.AlertRule {
	return db.AlertRule{
		ID:              id,
		Name:            "Device Offline",
		DeviceID:        &deviceID,
		ConditionType:   string(domain.ConditionDeviceOffline),
		Threshold:       1,
		ChannelID:       channelID,
		Enabled:         1,
		CooldownSeconds: cooldown,
	}
}

func heartbeatFailRule(id int64, deviceID *int64, channelID int64, threshold int64, cooldown int64) db.AlertRule {
	return db.AlertRule{
		ID:              id,
		Name:            "Heartbeat Fail",
		DeviceID:        deviceID,
		ConditionType:   string(domain.ConditionHeartbeatFail),
		Threshold:       threshold,
		ChannelID:       channelID,
		Enabled:         1,
		CooldownSeconds: cooldown,
	}
}

func heartbeatTimeoutRule(id int64, channelID int64, threshold int64, cooldown int64) db.AlertRule {
	return db.AlertRule{
		ID:              id,
		Name:            "Heartbeat Timeout",
		DeviceID:        nil,
		ConditionType:   string(domain.ConditionHeartbeatTimeout),
		Threshold:       threshold,
		ChannelID:       channelID,
		Enabled:         1,
		CooldownSeconds: cooldown,
	}
}

func enabledChannel(id int64) db.NotificationChannel {
	return db.NotificationChannel{
		ID:      id,
		Name:    "Test Channel",
		Type:    "webhook",
		Config:  `{"url": "http://localhost/test"}`,
		Enabled: 1,
	}
}

func disabledChannel(id int64) db.NotificationChannel {
	return db.NotificationChannel{
		ID:      id,
		Name:    "Disabled Channel",
		Type:    "webhook",
		Config:  `{"url": "http://localhost/test"}`,
		Enabled: 0,
	}
}

// --- Tests ---

func TestDeviceOfflineTriggersGlobalRule(t *testing.T) {
	store := &mockRuleStore{
		rules:    []db.AlertRule{globalOfflineRule(1, 10, 0)},
		channels: map[int64]db.NotificationChannel{10: enabledChannel(10)},
	}

	e, disp := newEngineWithRealDispatcher(store)
	defer disp.Stop()
	ctx := context.Background()

	err := e.EvaluateDeviceStatus(ctx, 1, "online", "offline")
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, store.updateCount(), "should update last_triggered_at")
	assert.Equal(t, 1, store.logCount(), "should log notification")
}

func TestDeviceOfflineTriggersDeviceSpecificRule(t *testing.T) {
	store := &mockRuleStore{
		rules: []db.AlertRule{
			globalOfflineRule(1, 10, 0),
			deviceOfflineRule(2, 42, 11, 0),
		},
		channels: map[int64]db.NotificationChannel{10: enabledChannel(10), 11: enabledChannel(11)},
	}

	e, disp := newEngineWithRealDispatcher(store)
	defer disp.Stop()
	ctx := context.Background()

	err := e.EvaluateDeviceStatus(ctx, 42, "online", "offline")
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 2, store.updateCount(), "both global and device-specific rules should fire")
	assert.Equal(t, 2, store.logCount(), "should log 2 notifications")
}

func TestDeviceSpecificRuleDoesNotFireForOtherDevice(t *testing.T) {
	store := &mockRuleStore{
		rules: []db.AlertRule{
			deviceOfflineRule(1, 42, 10, 0),
		},
		channels: map[int64]db.NotificationChannel{10: enabledChannel(10)},
	}

	e, disp := newEngineWithRealDispatcher(store)
	defer disp.Stop()
	ctx := context.Background()

	err := e.EvaluateDeviceStatus(ctx, 99, "online", "offline")
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, store.updateCount(), "device-specific rule should not fire for other device")
}

func TestNoDispatchOnOnlineTransition(t *testing.T) {
	store := &mockRuleStore{
		rules: []db.AlertRule{
			deviceOfflineRule(1, 42, 10, 0),
		},
		channels: map[int64]db.NotificationChannel{10: enabledChannel(10)},
	}

	e, disp := newEngineWithRealDispatcher(store)
	defer disp.Stop()
	ctx := context.Background()

	err := e.EvaluateDeviceStatus(ctx, 42, "offline", "online")
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, store.updateCount(), "offline rule should not fire on online transition")
}

func TestNoDispatchOnSameStatus(t *testing.T) {
	store := &mockRuleStore{
		rules:    []db.AlertRule{globalOfflineRule(1, 10, 0)},
		channels: map[int64]db.NotificationChannel{10: enabledChannel(10)},
	}

	e, disp := newEngineWithRealDispatcher(store)
	defer disp.Stop()
	ctx := context.Background()

	err := e.EvaluateDeviceStatus(ctx, 1, "offline", "offline")
	require.NoError(t, err)
	assert.Equal(t, 0, store.updateCount(), "no dispatch when status unchanged")
}

func TestCooldownPreventsDuplicateAlerts(t *testing.T) {
	now := time.Now()
	store := &mockRuleStore{
		rules: []db.AlertRule{
			func() db.AlertRule {
				r := globalOfflineRule(1, 10, 300) // 5 minute cooldown
				r.LastTriggeredAt = &now
				return r
			}(),
		},
		channels: map[int64]db.NotificationChannel{10: enabledChannel(10)},
	}

	e, disp := newEngineWithRealDispatcher(store)
	defer disp.Stop()
	ctx := context.Background()

	err := e.EvaluateDeviceStatus(ctx, 1, "online", "offline")
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, store.updateCount(), "cooldown should prevent re-trigger")
}

func TestCooldownExpires(t *testing.T) {
	old := time.Now().Add(-10 * time.Minute)
	store := &mockRuleStore{
		rules: []db.AlertRule{
			func() db.AlertRule {
				r := globalOfflineRule(1, 10, 300) // 5 minute cooldown
				r.LastTriggeredAt = &old
				return r
			}(),
		},
		channels: map[int64]db.NotificationChannel{10: enabledChannel(10)},
	}

	e, disp := newEngineWithRealDispatcher(store)
	defer disp.Stop()
	ctx := context.Background()

	err := e.EvaluateDeviceStatus(ctx, 1, "online", "offline")
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, store.updateCount(), "expired cooldown should allow re-trigger")
}

func TestDisabledChannelSkips(t *testing.T) {
	store := &mockRuleStore{
		rules:    []db.AlertRule{globalOfflineRule(1, 20, 0)},
		channels: map[int64]db.NotificationChannel{20: disabledChannel(20)},
	}

	e, disp := newEngineWithRealDispatcher(store)
	defer disp.Stop()
	ctx := context.Background()

	err := e.EvaluateDeviceStatus(ctx, 1, "online", "offline")
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, store.updateCount(), "disabled channel should not dispatch")
}

func TestEvaluateHeartbeatFail(t *testing.T) {
	store := &mockRuleStore{
		rules: []db.AlertRule{
			heartbeatFailRule(1, nil, 10, 3, 0),
		},
		channels: map[int64]db.NotificationChannel{10: enabledChannel(10)},
	}

	e, disp := newEngineWithRealDispatcher(store)
	defer disp.Stop()
	ctx := context.Background()

	result := &db.HeartbeatResult{
		DeviceID: 1,
		Status:   "fail",
	}

	// Below threshold
	err := e.EvaluateHeartbeatResult(ctx, 1, result, 2, 0)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, store.updateCount(), "below threshold should not fire")

	// At threshold
	err = e.EvaluateHeartbeatResult(ctx, 1, result, 3, 0)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, store.updateCount(), "at threshold should fire")
}

func TestEvaluateHeartbeatTimeout(t *testing.T) {
	store := &mockRuleStore{
		rules: []db.AlertRule{
			heartbeatTimeoutRule(1, 10, 2, 0),
		},
		channels: map[int64]db.NotificationChannel{10: enabledChannel(10)},
	}

	e, disp := newEngineWithRealDispatcher(store)
	defer disp.Stop()
	ctx := context.Background()

	result := &db.HeartbeatResult{
		DeviceID: 1,
		Status:   "timeout",
	}

	err := e.EvaluateHeartbeatResult(ctx, 1, result, 0, 1)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, store.updateCount(), "timeout below threshold should not fire")

	err = e.EvaluateHeartbeatResult(ctx, 1, result, 0, 2)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, store.updateCount(), "timeout at threshold should fire")

}

func TestHeartbeatSuccessDoesNotTriggerFailRule(t *testing.T) {
	store := &mockRuleStore{
		rules: []db.AlertRule{
			heartbeatFailRule(1, nil, 10, 1, 0),
		},
		channels: map[int64]db.NotificationChannel{10: enabledChannel(10)},
	}

	e, disp := newEngineWithRealDispatcher(store)
	defer disp.Stop()
	ctx := context.Background()

	result := &db.HeartbeatResult{
		DeviceID: 1,
		Status:   "success",
	}

	err := e.EvaluateHeartbeatResult(ctx, 1, result, 5, 0)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, store.updateCount(), "success result should not trigger fail rule")
}

func TestHeartbeatFailDoesNotTriggerTimeoutRule(t *testing.T) {
	store := &mockRuleStore{
		rules: []db.AlertRule{
			heartbeatTimeoutRule(1, 10, 1, 0),
		},
		channels: map[int64]db.NotificationChannel{10: enabledChannel(10)},
	}

	e, disp := newEngineWithRealDispatcher(store)
	defer disp.Stop()
	ctx := context.Background()

	result := &db.HeartbeatResult{
		DeviceID: 1,
		Status:   "fail",
	}

	err := e.EvaluateHeartbeatResult(ctx, 1, result, 5, 0)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, store.updateCount(), "fail result should not trigger timeout rule")
}

// --- Unit tests for internal methods ---

func TestRuleMatchesCondition_DeviceOffline(t *testing.T) {
	store := &mockRuleStore{}
	e := NewEngine(store, nil)

	tests := []struct {
		name string
		rule db.AlertRule
		old  string
		new  string
		want bool
	}{
		{"offline transition matches", globalOfflineRule(1, 10, 0), "online", "offline", true},
		{"online transition does not match", globalOfflineRule(1, 10, 0), "offline", "online", false},
		{"unknown to offline matches", globalOfflineRule(1, 10, 0), "unknown", "offline", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.matchesCondition(tt.rule, 1, tt.old, tt.new, nil, 0, 0)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRuleMatchesCondition_HeartbeatFail(t *testing.T) {
	store := &mockRuleStore{}
	e := NewEngine(store, nil)

	tests := []struct {
		name      string
		threshold int64
		status    string
		failCount int
		want      bool
	}{
		{"below threshold", 3, "fail", 2, false},
		{"at threshold", 3, "fail", 3, true},
		{"above threshold", 3, "fail", 5, true},
		{"success status", 3, "success", 3, false},
		{"timeout status", 3, "timeout", 3, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := heartbeatFailRule(1, nil, 10, tt.threshold, 0)
			st := tt.status
			got := e.matchesCondition(rule, 1, "", "", &st, tt.failCount, 0)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRuleMatchesCondition_HeartbeatTimeout(t *testing.T) {
	store := &mockRuleStore{}
	e := NewEngine(store, nil)

	tests := []struct {
		name         string
		threshold    int64
		status       string
		timeoutCount int
		want         bool
	}{
		{"below threshold", 2, "timeout", 1, false},
		{"at threshold", 2, "timeout", 2, true},
		{"fail status", 2, "fail", 3, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := heartbeatTimeoutRule(1, 10, tt.threshold, 0)
			st := tt.status
			got := e.matchesCondition(rule, 1, "", "", &st, 0, tt.timeoutCount)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRuleAppliesToDevice(t *testing.T) {
	store := &mockRuleStore{}
	e := NewEngine(store, nil)

	global := globalOfflineRule(1, 10, 0)
	device42 := deviceOfflineRule(2, 42, 10, 0)

	assert.True(t, e.ruleAppliesToDevice(global, 1), "global rule applies to any device")
	assert.True(t, e.ruleAppliesToDevice(global, 42), "global rule applies to device 42")
	assert.False(t, e.ruleAppliesToDevice(device42, 1), "device-specific rule does not apply to other device")
	assert.True(t, e.ruleAppliesToDevice(device42, 42), "device-specific rule applies to its device")
}

func TestInCooldown(t *testing.T) {
	store := &mockRuleStore{}
	e := NewEngine(store, nil)
	now := time.Now()

	tests := []struct {
		name     string
		lastTrig *time.Time
		cooldown int64
		want     bool
	}{
		{"never triggered", nil, 300, false},
		{"no cooldown", nil, 0, false},
		{"within cooldown", &now, 300, true},
		{"cooldown expired", ptrTime(now.Add(-10 * time.Minute)), 300, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := globalOfflineRule(1, 10, tt.cooldown)
			rule.LastTriggeredAt = tt.lastTrig
			got := e.inCooldown(rule, now)
			assert.Equal(t, tt.want, got)
		})
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

func TestNoRulesNoError(t *testing.T) {
	store := &mockRuleStore{
		rules:    []db.AlertRule{},
		channels: map[int64]db.NotificationChannel{},
	}

	e, disp := newEngineWithRealDispatcher(store)
	defer disp.Stop()
	ctx := context.Background()

	err := e.EvaluateDeviceStatus(ctx, 1, "online", "offline")
	require.NoError(t, err)
	assert.Equal(t, 0, store.updateCount())
}
