// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package diagnostics

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/domain"
	_ "modernc.org/sqlite"
)

// setupTestDB creates an in-memory SQLite database with the tables the
// diagnosis engine reads (devices incl. generated columns, device_sightings,
// scan_snapshots, device_network_presence, change_log) and returns the
// queries handle.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	// devices: full column set (GetDevice selects every column) + the four
	// generated projection columns the sibling query uses.
	_, err = conn.Exec(`
		CREATE TABLE devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_uuid TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'other' CHECK(type IN ('pc', 'embedded', 'iot', 'other', 'server', 'switch', 'router', 'firewall', 'nas')),
			brand TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			location TEXT NOT NULL DEFAULT '',
			purpose TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'unknown' CHECK(status IN ('online', 'offline', 'unknown')),
			ip_address TEXT NOT NULL DEFAULT '',
			mac_address TEXT NOT NULL DEFAULT '',
			serial_number TEXT NOT NULL DEFAULT '',
			purchase_date TEXT NOT NULL DEFAULT '',
			warranty_expiry TEXT NOT NULL DEFAULT '',
			tags TEXT NOT NULL DEFAULT '{}',
			scan_source TEXT NOT NULL DEFAULT 'manual',
			prometheus_labels TEXT NOT NULL DEFAULT '{}',
			last_scanned_at TIMESTAMP,
			last_scan_task_id INTEGER,
			open_ports TEXT NOT NULL DEFAULT '[]',
			detected_services TEXT NOT NULL DEFAULT '[]',
			prometheus_url TEXT NOT NULL DEFAULT '',
			node_exporter_url TEXT NOT NULL DEFAULT '',
			last_scan_rtt_ms INTEGER NOT NULL DEFAULT 0,
			scan_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(scan_attributes)),
			user_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(user_attributes)),
			scan_vendor   TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.vendor')) STORED,
			scan_mac      TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.mac')) STORED,
			scan_os       TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.os')) STORED,
			scan_hostname TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.hostname')) STORED,
			network_id INTEGER,
			ssh_credential_id INTEGER,
			first_seen TIMESTAMP,
			last_seen TIMESTAMP,
			offline_since TIMESTAMP,
			archived_at TIMESTAMP,
			archive_pin TEXT NOT NULL DEFAULT '',
			archive_offline_days_override INTEGER,
			online_since TIMESTAMP,
			periodic INTEGER NOT NULL DEFAULT 0,
			periodic_cycle_days REAL NOT NULL DEFAULT 0,
			lifecycle_state TEXT NOT NULL DEFAULT 'in_use',
			owner TEXT NOT NULL DEFAULT '',
			asset_no TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`)
	require.NoError(t, err)

	_, err = conn.Exec(`
		CREATE TABLE device_sightings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			ip_address TEXT NOT NULL DEFAULT '',
			mac_address TEXT NOT NULL DEFAULT '',
			network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
			vantage TEXT NOT NULL DEFAULT '',
			source TEXT NOT NULL DEFAULT '',
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			see_count INTEGER NOT NULL DEFAULT 1,
			UNIQUE(device_id, ip_address, mac_address, vantage, source)
		)`)
	require.NoError(t, err)

	_, err = conn.Exec(`
		CREATE TABLE scan_snapshots (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			network_id INTEGER NOT NULL,
			task_id INTEGER,
			ip TEXT NOT NULL,
			mac TEXT NOT NULL DEFAULT '',
			device_uuid TEXT NOT NULL DEFAULT '',
			miss_count INTEGER NOT NULL DEFAULT 0,
			last_seen_at DATETIME NOT NULL,
			flap_count INTEGER NOT NULL DEFAULT 0,
			last_flap_at DATETIME,
			UNIQUE(network_id, ip)
		)`)
	require.NoError(t, err)

	_, err = conn.Exec(`
		CREATE TABLE device_network_presence (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
			network_id INTEGER NOT NULL,
			ip_address TEXT NOT NULL DEFAULT '',
			vantage TEXT NOT NULL DEFAULT '',
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			UNIQUE(device_id, network_id)
		)`)
	require.NoError(t, err)

	_, err = conn.Exec(`
		CREATE TABLE change_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			agent_id TEXT,
			network_id INTEGER,
			change_type TEXT NOT NULL,
			entity_type TEXT NOT NULL,
			entity_id INTEGER,
			before_data TEXT,
			after_data TEXT,
			detected_at DATETIME NOT NULL
		)`)
	require.NoError(t, err)

	return conn
}

func insertDevice(t *testing.T, conn *sql.DB, name, status, ip, mac, attrsJSON string, networkID *int64) int64 {
	t.Helper()
	res, err := conn.Exec(`
		INSERT INTO devices (name, status, ip_address, mac_address, scan_attributes, network_id)
		VALUES (?, ?, ?, ?, ?, ?)`,
		name, status, ip, mac, attrsJSON, networkID)
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

func insertSighting(t *testing.T, conn *sql.DB, deviceID int64, ip, mac string, netID int64, source string, first, last time.Time, count int64) {
	t.Helper()
	_, err := conn.Exec(`
		INSERT INTO device_sightings (device_id, ip_address, mac_address, network_id, vantage, source, first_seen, last_seen, see_count)
		VALUES (?, ?, ?, ?, 'agent-a', ?, ?, ?, ?)`,
		deviceID, ip, mac, nullIfZero(netID), source, first, last, count)
	require.NoError(t, err)
}

func insertSnapshot(t *testing.T, conn *sql.DB, netID int64, ip string, miss, flap int64) {
	t.Helper()
	_, err := conn.Exec(`
		INSERT INTO scan_snapshots (network_id, ip, miss_count, last_seen_at, flap_count)
		VALUES (?, ?, ?, ?, ?)`,
		netID, ip, miss, time.Now(), flap)
	require.NoError(t, err)
}

func insertPresence(t *testing.T, conn *sql.DB, deviceID, netID int64, ip string) {
	t.Helper()
	_, err := conn.Exec(`
		INSERT INTO device_network_presence (device_id, network_id, ip_address, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?)`,
		deviceID, netID, ip, time.Now().Add(-time.Hour), time.Now())
	require.NoError(t, err)
}

func insertChange(t *testing.T, conn *sql.DB, deviceID int64, changeType, before, after string) {
	t.Helper()
	_, err := conn.Exec(`
		INSERT INTO change_log (change_type, entity_type, entity_id, before_data, after_data, detected_at)
		VALUES (?, 'device', ?, ?, ?, ?)`,
		changeType, deviceID, before, after, time.Now())
	require.NoError(t, err)
}

func nullIfZero(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

func mustDiagnose(t *testing.T, conn *sql.DB, deviceID int64) *domain.DeviceNetworkDiagnosis {
	t.Helper()
	svc := NewService(conn)
	out, err := svc.Diagnose(context.Background(), deviceID)
	require.NoError(t, err)
	return out
}

func findingByCode(out *domain.DeviceNetworkDiagnosis, code domain.DiagnosisFindingCode) *domain.DiagnosisFinding {
	for i := range out.Findings {
		if out.Findings[i].Code == code {
			return &out.Findings[i]
		}
	}
	return nil
}

// TestStaleARPArtifact pins the field-verified incident signature (#761): one
// MAC sighted at many addresses, none of which ever answered a scan, on an
// offline row — the address drift is a stale ARP-cache artifact.
func TestStaleARPArtifact(t *testing.T) {
	conn := setupTestDB(t)
	now := time.Now()
	ghostMAC := "7c:83:34:bb:16:2a"

	ghost := insertDevice(t, conn, "ghost-box", "offline", "192.0.2.131",
		ghostMAC, `{"hostname":"ghost-box","mac":"`+ghostMAC+`"}`, ptrInt64(4))

	// 5 sighted addresses; the current one plus 4 ghosts that never answered.
	insertSighting(t, conn, ghost, "192.0.2.131", ghostMAC, 4, "scan", now.Add(-time.Hour), now, 12)
	insertSighting(t, conn, ghost, "192.0.2.42", ghostMAC, 4, "scan", now.Add(-2*time.Hour), now.Add(-time.Minute), 30)
	insertSighting(t, conn, ghost, "192.0.2.100", ghostMAC, 4, "scan", now.Add(-3*time.Hour), now.Add(-2*time.Minute), 4)
	insertSighting(t, conn, ghost, "192.0.2.107", ghostMAC, 4, "scan", now.Add(-4*time.Hour), now.Add(-3*time.Minute), 3)
	insertSighting(t, conn, ghost, "192.0.2.115", ghostMAC, 4, "scan", now.Add(-5*time.Hour), now.Add(-4*time.Minute), 2)
	// No scan_snapshots rows at all: the addresses never answered a scan.

	out := mustDiagnose(t, conn, ghost)

	require.Equal(t, "anomaly", out.Status)
	require.Equal(t, domain.DiagnosisStaleARPArtifact, out.Classification)
	require.Equal(t, "high", out.Confidence)
	require.Equal(t, "critical", string(findingByCode(out, domain.DiagnosisStaleARPArtifact).Severity))
	require.Len(t, out.Addresses, 5)
	require.False(t, out.Addresses[1].Alive, "ghost addresses must carry no liveness")
	require.Equal(t, -1, out.Addresses[1].MissingScans, "no snapshot = never seen alive")
	// Evidence chain: 1 sighting fact + 4 dead-address snapshot facts + offline.
	f := findingByCode(out, domain.DiagnosisStaleARPArtifact)
	require.GreaterOrEqual(t, len(f.Evidence), 5)
}

// TestHealthyDevice: one address, alive in the latest scan, online row —
// verdict is healthy with no findings.
func TestHealthyDevice(t *testing.T) {
	conn := setupTestDB(t)
	now := time.Now()
	mac := "00:11:22:33:44:55"

	dev := insertDevice(t, conn, "steady", "online", "192.0.2.10", mac,
		`{"hostname":"steady"}`, ptrInt64(1))
	insertSighting(t, conn, dev, "192.0.2.10", mac, 1, "scan", now.Add(-time.Hour), now, 100)
	insertSnapshot(t, conn, 1, "192.0.2.10", 0, 0)

	out := mustDiagnose(t, conn, dev)
	require.Equal(t, "healthy", out.Status)
	require.Empty(t, out.Classification)
	require.Empty(t, out.Findings)
	require.Len(t, out.Addresses, 1)
	require.True(t, out.Addresses[0].Alive)
	require.Equal(t, 0, out.Addresses[0].MissingScans)
}

// TestMultihomedAlias: presence rows in two networks (or engine ip_aliases)
// classify as dual-homed info, not as drift.
func TestMultihomedAlias(t *testing.T) {
	conn := setupTestDB(t)
	now := time.Now()
	mac := "aa:bb:cc:00:11:22"

	dev := insertDevice(t, conn, "bridge-box", "online", "192.0.2.2", mac,
		`{"hostname":"bridge-box","extras":{"ip_aliases":"192.0.2.3,192.0.2.4"}}`, ptrInt64(1))
	insertSighting(t, conn, dev, "192.0.2.2", mac, 1, "scan", now.Add(-time.Hour), now, 50)
	insertSnapshot(t, conn, 1, "192.0.2.2", 0, 0)
	insertPresence(t, conn, dev, 1, "192.0.2.2")
	insertPresence(t, conn, dev, 2, "10.0.0.2")

	out := mustDiagnose(t, conn, dev)
	require.Equal(t, "watch", out.Status)
	f := findingByCode(out, domain.DiagnosisMultihomedAlias)
	require.NotNil(t, f, "two fresh presence rows must classify as multihomed")
	require.Equal(t, "info", string(f.Severity))
}

// TestLocallyAdministeredMAC: the U/L-bit attribute surfaces as an info
// finding (MAC binding will not hold) — neutral fact, never a verdict.
func TestLocallyAdministeredMAC(t *testing.T) {
	conn := setupTestDB(t)
	now := time.Now()

	dev := insertDevice(t, conn, "vm-guest", "online", "192.0.2.20", "",
		`{"hostname":"vm-guest","mac_is_locally_administered":true}`, ptrInt64(1))
	insertSighting(t, conn, dev, "192.0.2.20", "92:59:32:42:1d:31", 1, "scan", now.Add(-time.Hour), now, 10)
	insertSnapshot(t, conn, 1, "192.0.2.20", 0, 0)

	out := mustDiagnose(t, conn, dev)
	require.NotNil(t, findingByCode(out, domain.DiagnosisLocallyAdministeredMAC))
	require.Equal(t, "watch", out.Status)
}

// TestIPSlotTakeover: a device_changed row where the MAC swapped at an
// unchanged address is the takeover signature.
func TestIPSlotTakeover(t *testing.T) {
	conn := setupTestDB(t)
	now := time.Now()
	mac := "10:66:6a:f1:71:3f"

	dev := insertDevice(t, conn, "swapped-slot", "online", "192.0.2.115", mac,
		`{"hostname":"swapped-slot"}`, ptrInt64(4))
	insertSighting(t, conn, dev, "192.0.2.115", mac, 4, "scan", now.Add(-time.Hour), now, 5)
	insertSnapshot(t, conn, 4, "192.0.2.115", 0, 0)
	insertChange(t, conn, dev, "device_changed",
		`{"name":"pgsql-01","mac_address":"10:66:6a:f1:71:3f","ip_address":"192.0.2.115"}`,
		`{"name":"n305-server","mac_address":"7c:83:34:bb:16:2a","ip_address":"192.0.2.115"}`)

	out := mustDiagnose(t, conn, dev)
	require.Equal(t, "anomaly", out.Status)
	require.Equal(t, domain.DiagnosisIPSlotTakeover, out.Classification)
}

// TestHostnameIdentitySplit: sibling rows announcing the same hostname under
// different MACs are listed and classified as an identity split.
func TestHostnameIdentitySplit(t *testing.T) {
	conn := setupTestDB(t)
	now := time.Now()
	mac := "7c:83:34:bb:16:2a"

	dev := insertDevice(t, conn, "n305-server", "online", "192.0.2.131", mac,
		`{"hostname":"n305-server"}`, ptrInt64(4))
	insertSighting(t, conn, dev, "192.0.2.131", mac, 4, "scan", now.Add(-time.Hour), now, 9)
	insertSnapshot(t, conn, 4, "192.0.2.131", 0, 0)

	sibMAC := "7c:83:34:bb:16:2b"
	sib := insertDevice(t, conn, "n305-server.tail.ts.net", "online", "192.0.2.177", sibMAC,
		`{"hostname":"n305-server"}`, ptrInt64(4))
	require.NotZero(t, sib)
	insertSighting(t, conn, sib, "192.0.2.177", sibMAC, 4, "scan", now.Add(-time.Hour), now, 40)
	insertSnapshot(t, conn, 4, "192.0.2.177", 0, 0)

	out := mustDiagnose(t, conn, dev)
	require.Len(t, out.Siblings, 1)
	require.Equal(t, sib, out.Siblings[0].ID)
	require.NotNil(t, findingByCode(out, domain.DiagnosisHostnameSplit))
}

// TestDeviceNotFound: an unknown id maps to the sentinel error.
func TestDeviceNotFound(t *testing.T) {
	conn := setupTestDB(t)
	svc := NewService(conn)
	_, err := svc.Diagnose(context.Background(), 9999)
	require.ErrorIs(t, err, ErrDeviceNotFound)
}

func ptrInt64(v int64) *int64 { return &v }
