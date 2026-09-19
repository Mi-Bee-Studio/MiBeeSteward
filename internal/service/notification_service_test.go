// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"

	"github.com/stretchr/testify/require"
)

func setupNotificationService(t *testing.T) (*NotificationService, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return NewNotificationService(db.New(conn)), conn
}

func createWebhookChannel(t *testing.T, svc *NotificationService, name string) *domain.ChannelResponse {
	t.Helper()
	ch, err := svc.CreateChannel(context.Background(), domain.CreateChannelRequest{
		Name:   name,
		Type:   domain.ChannelTypeWebhook,
		Config: json.RawMessage(`{"url":"https://example.com/hook"}`),
	})
	require.NoError(t, err)
	return ch
}

// --- Channel CRUD ---

func TestNotificationChannel_CRUD(t *testing.T) {
	svc, _ := setupNotificationService(t)
	ctx := context.Background()

	created := createWebhookChannel(t, svc, "ops-hook")
	require.NotZero(t, created.ID)
	require.True(t, created.Enabled) // defaults to enabled
	require.Equal(t, "webhook", created.Type)
	require.JSONEq(t, `{"url":"https://example.com/hook"}`, string(created.Config))

	// explicit enabled=false on create
	disabled := false
	off, err := svc.CreateChannel(ctx, domain.CreateChannelRequest{
		Name:    "quiet-hook",
		Type:    domain.ChannelTypeFeishu,
		Enabled: &disabled,
	})
	require.NoError(t, err)
	require.False(t, off.Enabled)

	all, err := svc.ListChannels(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2)

	got, err := svc.GetChannel(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "ops-hook", got.Name)

	// partial update: nil fields keep existing values
	newName := "renamed-hook"
	updated, err := svc.UpdateChannel(ctx, created.ID, domain.UpdateChannelRequest{Name: &newName})
	require.NoError(t, err)
	require.Equal(t, "renamed-hook", updated.Name)
	require.Equal(t, "webhook", updated.Type)
	require.True(t, updated.Enabled)
	require.JSONEq(t, `{"url":"https://example.com/hook"}`, string(updated.Config))

	// invalid type on update is rejected without mutating the row
	badType := domain.ChannelType("carrier-pigeon")
	_, err = svc.UpdateChannel(ctx, created.ID, domain.UpdateChannelRequest{Type: &badType})
	require.ErrorIs(t, err, ErrInvalidChannelConfig)
	same, err := svc.GetChannel(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "webhook", same.Type)

	// single-field enable toggle (the UI switch path — must not rewrite config)
	toggled, err := svc.SetChannelEnabled(ctx, created.ID, false)
	require.NoError(t, err)
	require.False(t, toggled.Enabled)
	require.JSONEq(t, `{"url":"https://example.com/hook"}`, string(toggled.Config))
	backOn, err := svc.SetChannelEnabled(ctx, created.ID, true)
	require.NoError(t, err)
	require.True(t, backOn.Enabled)

	require.NoError(t, svc.DeleteChannel(ctx, created.ID))
}

func TestNotificationChannel_ValidationAndNotFound(t *testing.T) {
	svc, _ := setupNotificationService(t)
	ctx := context.Background()

	_, err := svc.CreateChannel(ctx, domain.CreateChannelRequest{Type: domain.ChannelTypeWebhook})
	require.ErrorIs(t, err, ErrInvalidChannelConfig)

	_, err = svc.CreateChannel(ctx, domain.CreateChannelRequest{Name: "x", Type: domain.ChannelType("sms")})
	require.ErrorIs(t, err, ErrInvalidChannelConfig)

	_, err = svc.GetChannel(ctx, 9999)
	require.ErrorIs(t, err, ErrChannelNotFound)

	_, err = svc.UpdateChannel(ctx, 9999, domain.UpdateChannelRequest{})
	require.ErrorIs(t, err, ErrChannelNotFound)

	_, err = svc.SetChannelEnabled(ctx, 9999, true)
	require.ErrorIs(t, err, ErrChannelNotFound)
}

// --- Rule CRUD ---

func TestNotificationRule_CRUD(t *testing.T) {
	svc, _ := setupNotificationService(t)
	ctx := context.Background()

	channel := createWebhookChannel(t, svc, "ops-hook")

	created, err := svc.CreateRule(ctx, domain.CreateRuleRequest{
		Name: "lost-devices", EventType: "device_lost", ScopeType: domain.RuleScopeAll,
		ChannelID: channel.ID,
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)
	require.Equal(t, 30, created.CooldownMinutes) // 0 → default 30
	require.True(t, created.Enabled)

	networkID := int64(7)
	scoped, err := svc.CreateRule(ctx, domain.CreateRuleRequest{
		Name: "net-scoped", EventType: "device_added", ScopeType: domain.RuleScopeNetwork,
		ScopeNetworkID: &networkID, ChannelID: channel.ID, CooldownMinutes: 5,
	})
	require.NoError(t, err)
	require.Equal(t, 5, scoped.CooldownMinutes)
	require.NotNil(t, scoped.ScopeNetworkID)

	rules, err := svc.ListRules(ctx)
	require.NoError(t, err)
	require.Len(t, rules, 2)

	got, err := svc.GetRule(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "lost-devices", got.Name)

	// full-replace update; cooldown over the cap clamps to 7 days
	updated, err := svc.UpdateRule(ctx, created.ID, domain.UpdateRuleRequest{
		Name: "lost-v2", EventType: "device_changed", ScopeType: domain.RuleScopeDevice,
		ScopeDeviceUUID: "uuid-abc", ChannelID: channel.ID, CooldownMinutes: 99999,
	})
	require.NoError(t, err)
	require.Equal(t, "lost-v2", updated.Name)
	require.Equal(t, 10080, updated.CooldownMinutes)

	_, err = svc.UpdateRule(ctx, 9999, domain.UpdateRuleRequest{
		Name: "ghost", EventType: "device_lost", ScopeType: "all", ChannelID: channel.ID,
	})
	require.ErrorIs(t, err, ErrRuleNotFound)

	// single-field enable toggle
	off, err := svc.SetRuleEnabled(ctx, created.ID, false)
	require.NoError(t, err)
	require.False(t, off.Enabled)

	// hot-path query only returns enabled rules for the event type
	matching, err := svc.ListEnabledRulesByEventType(ctx, "device_added")
	require.NoError(t, err)
	require.Len(t, matching, 1)
	require.Equal(t, "net-scoped", matching[0].Name)

	require.NoError(t, svc.DeleteRule(ctx, created.ID))
	_, err = svc.GetRule(ctx, created.ID)
	require.ErrorIs(t, err, ErrRuleNotFound)
}

func TestNotificationRule_FieldValidation(t *testing.T) {
	svc, _ := setupNotificationService(t)
	ctx := context.Background()
	channel := createWebhookChannel(t, svc, "ops-hook")
	netID := int64(1)

	cases := []struct {
		name string
		req  domain.CreateRuleRequest
	}{
		{"missing name", domain.CreateRuleRequest{EventType: "device_lost", ScopeType: "all", ChannelID: channel.ID}},
		{"bad event type", domain.CreateRuleRequest{Name: "r", EventType: "device_exploded", ScopeType: "all", ChannelID: channel.ID}},
		{"bad scope type", domain.CreateRuleRequest{Name: "r", EventType: "device_lost", ScopeType: "galaxy", ChannelID: channel.ID}},
		{"missing channel", domain.CreateRuleRequest{Name: "r", EventType: "device_lost", ScopeType: "all"}},
		{"network scope without id", domain.CreateRuleRequest{Name: "r", EventType: "device_lost", ScopeType: domain.RuleScopeNetwork, ChannelID: channel.ID}},
		{"device scope without uuid", domain.CreateRuleRequest{Name: "r", EventType: "device_lost", ScopeType: domain.RuleScopeDevice, ChannelID: channel.ID}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateRule(ctx, tc.req)
			require.ErrorIs(t, err, ErrInvalidRuleConfig)
		})
	}

	// same constraints hold on update
	_, err := svc.UpdateRule(ctx, 1, domain.UpdateRuleRequest{Name: "r", EventType: "device_lost", ScopeType: domain.RuleScopeNetwork, ChannelID: channel.ID})
	require.ErrorIs(t, err, ErrInvalidRuleConfig)

	// the valid network-scope shape passes validation itself
	_, err = svc.CreateRule(ctx, domain.CreateRuleRequest{
		Name: "ok", EventType: "device_lost", ScopeType: domain.RuleScopeNetwork,
		ScopeNetworkID: &netID, ChannelID: channel.ID,
	})
	require.NoError(t, err)
}

// --- Notification logs ---

func TestNotificationLogs_PaginationClampAndUserReadState(t *testing.T) {
	svc, conn := setupNotificationService(t)
	ctx := context.Background()

	// three sent logs + one failed
	for i := 0; i < 3; i++ {
		_, err := conn.Exec(`INSERT INTO notification_log (status, payload) VALUES ('sent', '{}')`)
		require.NoError(t, err)
	}
	_, err := conn.Exec(`INSERT INTO notification_log (status, payload, error_message) VALUES ('failed', '{}', 'dial timeout')`)
	require.NoError(t, err)

	// legacy system-wide view: limit/offset clamped, total = 4
	logs, total, err := svc.ListNotificationLogs(ctx, -5, -1)
	require.NoError(t, err)
	require.Equal(t, int64(4), total)
	require.Len(t, logs, 4)
	require.True(t, logs[0].IsRead) // legacy view has no read state → all read

	oversized, _, err := svc.ListNotificationLogs(ctx, 500, 0)
	require.NoError(t, err)
	require.Len(t, oversized, 4) // clamped to default limit 20

	// user 42 has not read anything → 4 unread
	rows, unread, err := svc.ListNotificationLogsForUser(ctx, 42, 10, 0)
	require.NoError(t, err)
	require.Equal(t, int64(4), unread)
	require.Len(t, rows, 4)
	for _, r := range rows {
		require.False(t, r.IsRead)
	}

	// mark all read: 4 newly marked, second call is a no-op
	n, err := svc.MarkAllNotificationLogsRead(ctx, 42)
	require.NoError(t, err)
	require.Equal(t, int64(4), n)
	n, err = svc.MarkAllNotificationLogsRead(ctx, 42)
	require.NoError(t, err)
	require.Zero(t, n)

	rows, unread, err = svc.ListNotificationLogsForUser(ctx, 42, 10, 0)
	require.NoError(t, err)
	require.Zero(t, unread)
	for _, r := range rows {
		require.True(t, r.IsRead)
	}

	// a different user's read state is untouched
	_, otherUnread, err := svc.ListNotificationLogsForUser(ctx, 43, 10, 0)
	require.NoError(t, err)
	require.Equal(t, int64(4), otherUnread)
}
