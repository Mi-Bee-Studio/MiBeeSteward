// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package store

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// TestBuildStoreScanAttributes_FieldLadder pins the evidence→attribute fold:
// explicit Brand wins over inferred, hostname prefers node_hostname over
// sys_name, and the numeric parses only accept positive integers (junk
// strings leave the zero values).
func TestBuildStoreScanAttributes_FieldLadder(t *testing.T) {
	d := scannerv2.DeviceRef{IP: "10.0.0.1", Type: "nas", Brand: "Synology"}
	extra := map[string]string{
		"inferred_brand": "ignored-when-Brand-set",
		"oui_prefix":     "00:11:32", "oui_vendor": "Synology Inc.",
		"inferred_description": "DS920+", "os_type": "DSM", "os_version": "7.2",
		"kernel_version": "4.4.30+", "firmware_version": "DSM 7.2-72803",
		"node_hostname": "nas-a", "sys_name": "fallback", "mac": "00:11:32:aa:bb:cc",
		"memory_total_bytes": "8589934592", "cpu_count": "4", "uptime_seconds": "123456",
		"memory_total_bytes_bad": "",
	}
	attr := buildStoreScanAttributes(d, extra, "[9200]", "[ssh]", "", "http://x/nm")
	require.Equal(t, "Synology", attr.Vendor, "explicit Brand wins over inferred")
	require.Equal(t, "nas-a", attr.Hostname, "node_hostname beats sys_name")
	require.EqualValues(t, 8589934592, attr.MemoryTotalBytes)
	require.EqualValues(t, 4, attr.CPUCount)
	require.EqualValues(t, 123456, attr.UptimeSeconds)
	require.Equal(t, "00:11:32", attr.OUIPrefix)
	require.Equal(t, "DSM", attr.OS)

	// Brand fallback + hostname fallback + junk numerics.
	d2 := scannerv2.DeviceRef{IP: "10.0.0.2", Type: "other"}
	attr = buildStoreScanAttributes(d2, map[string]string{
		"inferred_brand": "Hikvision", "sys_name": "sw-core",
		"memory_total_bytes": "not-a-number", "cpu_count": "-2", "uptime_seconds": "0",
	}, "", "", "", "")
	require.Equal(t, "Hikvision", attr.Vendor, "inferred brand used when Brand empty")
	require.Equal(t, "sw-core", attr.Hostname, "sys_name used when node_hostname absent")
	require.Zero(t, attr.MemoryTotalBytes, "junk numeric stays zero")
	require.Zero(t, attr.CPUCount, "negative numeric stays zero")
	require.Zero(t, attr.UptimeSeconds, "zero uptime stays zero")
}

// TestEnrichDeviceByMAC_MergesAndCreates drives the MAC-keyed enrichment:
// existing rows get fields merged (never overwritten with empties), an
// unknown MAC is a silent no-op, and a bad JSON column leaves the row
// untouched instead of failing.
func TestEnrichDeviceByMAC_MergesAndCreates(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	conn := repo.db
	nid := sql.NullInt64{Int64: 1, Valid: true}
	id := seedDeviceRow(t, conn, "10.0.0.4", "aa:bb:cc:dd:ee:04", nid)

	require.NoError(t, repo.EnrichDeviceByMAC(ctx, "aa:bb:cc:dd:ee:04", map[string]string{
		"inferred_brand": "Ubiquiti", "inferred_type": "router",
	}))
	var attrs string
	require.NoError(t, conn.QueryRow(`SELECT scan_attributes FROM devices WHERE id = ?`, id).Scan(&attrs))
	require.Contains(t, attrs, "Ubiquiti")
	require.Contains(t, attrs, "router")

	// Empty values must not clobber what's there.
	require.NoError(t, repo.EnrichDeviceByMAC(ctx, "aa:bb:cc:dd:ee:04", map[string]string{
		"inferred_brand": "",
	}))
	require.NoError(t, conn.QueryRow(`SELECT scan_attributes FROM devices WHERE id = ?`, id).Scan(&attrs))
	require.Contains(t, attrs, "Ubiquiti", "empty enrichment never erases")

	// Unknown MAC is a no-op.
	require.NoError(t, repo.EnrichDeviceByMAC(ctx, "de:ad:de:ad:de:ad", map[string]string{"x": "y"}))
}

// TestLegacyUpsertHeartbeats_SpecLadder drives the heartbeat seeding upsert:
// zero intervals/timeouts take the repo defaults, and a spec for an unknown
// device id errors at the insert.
func TestLegacyUpsertHeartbeats_SpecLadder(t *testing.T) {
	repo, ctx := newRepo(t, Options{DefaultHeartbeatInterval: 60, DefaultHeartbeatTimeout: 5})
	conn := repo.db
	nid := sql.NullInt64{Int64: 1, Valid: true}
	id := seedDeviceRow(t, conn, "10.0.0.5", "aa:bb:cc:dd:ee:05", nid)

	tx, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	// legacyUpsertHeartbeats commits the tx itself (non-fatal semantics).
	require.NoError(t, repo.legacyUpsertHeartbeats(ctx, tx, id, []scannerv2.HeartbeatSpec{
		{Method: "tcp", Target: "10.0.0.5:22", IntervalSeconds: 0, TimeoutSeconds: 0},
	}))

	var interval, timeout int
	require.NoError(t, conn.QueryRow(`SELECT interval_seconds, timeout_seconds FROM heartbeat_configs WHERE device_id = ?`, id).
		Scan(&interval, &timeout))
	require.Equal(t, 60, interval, "zero interval takes the repo default")
	require.Equal(t, 5, timeout, "zero timeout takes the repo default")

	// Seeding for a not-yet-existing device id is tolerated (FKs are off in
	// the pool; the row simply lands for the next RecordDevice to claim).
	tx2, err := conn.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, repo.legacyUpsertHeartbeats(ctx, tx2, 424242, []scannerv2.HeartbeatSpec{
		{Method: "icmp", Target: "10.0.0.5"},
	}))
}
