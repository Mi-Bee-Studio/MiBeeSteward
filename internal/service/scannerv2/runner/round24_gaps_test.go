// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package runner

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

var errHBStub = errors.New("hb stub failure")

// hbStub records every HeartbeatCreator call and can fail each method — the
// device bridge's seed/backfill branches need both outcomes.
type hbStub struct {
	resetCalls      []int64
	createCfgCalls  []int64
	defaultCfgCalls []int64
	samples         []string

	failCreate  bool
	failDefault bool
}

func (h *hbStub) CreateConfigs(_ context.Context, deviceID int64, _ []scannerv2.HeartbeatSpec) error {
	h.createCfgCalls = append(h.createCfgCalls, deviceID)
	if h.failCreate {
		return errHBStub
	}
	return nil
}

func (h *hbStub) CreateDefaultConfig(_ context.Context, deviceID int64, _ string) error {
	h.defaultCfgCalls = append(h.defaultCfgCalls, deviceID)
	if h.failDefault {
		return errHBStub
	}
	return nil
}

func (h *hbStub) ResetFailures(deviceID int64) {
	h.resetCalls = append(h.resetCalls, deviceID)
}

func (h *hbStub) SampleLiveness(_ int64, status, source string) {
	h.samples = append(h.samples, status+"@"+source)
}

// TestApplyDeviceBridge_OfflineToOnlineRecovery drives the recovery tier: a
// known-offline device that answers a scan emits device_recovered (NOT
// device_changed) and resets the heartbeat failure counter.
func TestApplyDeviceBridge_OfflineToOnlineRecovery(t *testing.T) {
	rn, queries, conn := setupChangeDetectDB(t)
	ctx := context.Background()

	ip, mac := "192.168.63.10", "6a:27:19:ac:fb:10"
	rep := reportFor(ip, "camera", "Hikvision", mac)
	_, _ = rn.applyDeviceBridge(ctx, rep, rn.networkID, "")
	var devID int64
	require.NoError(t, conn.QueryRow(`SELECT id FROM devices WHERE ip_address = ?`, ip).Scan(&devID))

	// The device drops offline (heartbeat misses / lease expiry), then a later
	// scan finds it alive again at the same ip/mac.
	_, err := conn.Exec(`UPDATE devices SET status='offline', offline_since='2026-01-01T00:00:00Z' WHERE id = ?`, devID)
	require.NoError(t, err)

	hb := &hbStub{}
	rn.heartbeat = hb
	_, _ = rn.applyDeviceBridge(ctx, rep, rn.networkID, "")

	require.Equal(t, "online", fetchDevice(t, conn, devID).Status)
	require.Contains(t, hb.resetCalls, devID, "scan-alive clears the heartbeat failure counter")

	events, err := queries.ListChangeLog(ctx, dbListAllParams())
	require.NoError(t, err)
	var recovered bool
	for _, e := range events {
		if e.ChangeType == "device_recovered" && e.EntityID != nil && *e.EntityID == devID {
			recovered = true
		}
	}
	require.True(t, recovered, "offline→online flip emits device_recovered")
}

// TestApplyDeviceBridge_BackfillsHeartbeatConfigs pins the backfill tier for
// pre-existing devices that predate the "always seed at least ICMP" rule:
// with zero configs, a re-scan with specs seeds those, without specs falls
// back to the ICMP default.
func TestApplyDeviceBridge_BackfillsHeartbeatConfigs(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	ctx := context.Background()

	ip, mac := "192.168.63.11", "6a:27:19:ac:fb:11"
	// First sighting lands with NO heartbeat wiring (the legacy shape).
	_, _ = rn.applyDeviceBridge(ctx, reportFor(ip, "nas", "Synology", mac), rn.networkID, "")
	var devID int64
	require.NoError(t, conn.QueryRow(`SELECT id FROM devices WHERE ip_address = ?`, ip).Scan(&devID))
	var cfgCount int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM heartbeat_configs WHERE device_id = ?`, devID).Scan(&cfgCount))
	require.Zero(t, cfgCount, "device created before the fallback rule has no configs")

	// A later scan (heartbeat service now wired) backfills from the report's
	// specs.
	hb := &hbStub{}
	rn.heartbeat = hb
	withSpecs := reportFor(ip, "nas", "Synology", mac)
	withSpecs.Heartbeats = []scannerv2.HeartbeatSpec{{Method: "http", Target: "http://" + ip + ":5001"}}
	_, _ = rn.applyDeviceBridge(ctx, withSpecs, rn.networkID, "")
	require.Equal(t, []int64{devID}, hb.createCfgCalls, "re-scan with specs seeds those configs")
	require.Empty(t, hb.defaultCfgCalls, "spec path must not also seed the ICMP default")

	// And a spec-less re-scan of a still-config-less device uses the default.
	hb2 := &hbStub{}
	rn.heartbeat = hb2
	_, _ = rn.applyDeviceBridge(ctx, reportFor(ip, "nas", "Synology", mac), rn.networkID, "")
	require.Equal(t, []int64{devID}, hb2.defaultCfgCalls, "spec-less re-scan seeds the ICMP fallback")
	require.Empty(t, hb2.createCfgCalls)
}

// TestApplyDeviceBridge_NewDeviceSeedHeartbeatErrors walks the new-device
// seeding warn branches: a failing CreateConfigs (specs present) and a failing
// CreateDefaultConfig (no specs) must not abort the bridge — the device row
// still lands.
func TestApplyDeviceBridge_NewDeviceSeedHeartbeatErrors(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	ctx := context.Background()

	hb := &hbStub{failCreate: true}
	rn.heartbeat = hb
	withSpecs := reportFor("192.168.63.12", "switch", "Mikrotik", "6a:27:19:ac:fb:12")
	withSpecs.Heartbeats = []scannerv2.HeartbeatSpec{{Method: "tcp", Target: "192.168.63.12:8291"}}
	_, _ = rn.applyDeviceBridge(ctx, withSpecs, rn.networkID, "")
	var n int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM devices WHERE ip_address = '192.168.63.12'`).Scan(&n))
	require.Equal(t, 1, n, "seed failure is logged, the device row persists")

	hb2 := &hbStub{failDefault: true}
	rn.heartbeat = hb2
	_, _ = rn.applyDeviceBridge(ctx, reportFor("192.168.63.13", "printer", "HP", "6a:27:19:ac:fb:13"), rn.networkID, "")
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM devices WHERE ip_address = '192.168.63.13'`).Scan(&n))
	require.Equal(t, 1, n)
}

// TestApplyDeviceBridge_ResolveFailureBails: when the identity lookup itself
// errors (connection gone), the bridge must bail WITHOUT writing anything.
func TestApplyDeviceBridge_ResolveFailureBails(t *testing.T) {
	rn, _, conn := setupChangeDetectDB(t)
	ctx := context.Background()
	require.NoError(t, conn.Close())

	created, _ := rn.applyDeviceBridge(ctx, reportFor("192.168.63.14", "camera", "Axis", "6a:27:19:ac:fb:14"), rn.networkID, "")
	require.False(t, created, "lookup failure must not create a device")
}
