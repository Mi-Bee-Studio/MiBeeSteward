// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

// Package demoseed builds the demo-mode experience (#285): a fully-populated
// fictional inventory seeded on first boot of an empty database, plus a
// low-frequency activity ticker that keeps the dashboard feeling alive
// (status flips → change_log rows, probe result waves). Everything is
// clearly fictional (device names, IPs in 198.51.100.0/24 — TEST-NET-2 —
// and 203.0.113.0/24 — TEST-NET-3, RFC 5737 documentation ranges) so demo
// data can never be confused with a real network.
package demoseed

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"time"
)

// IsDemoEmpty reports whether the database has no user-visible inventory yet
// (the gate for seeding: only a brand-new install gets the demo plane).
func IsDemoEmpty(dbConn *sql.DB) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var n int
	if err := dbConn.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices`).Scan(&n); err != nil {
		return false // cannot tell → do not seed (safe default)
	}
	return n == 0
}

type demoDevice struct {
	Name  string
	IP    string
	MAC   string
	Type  string
	Brand string
	Attrs string // scan_attributes JSON
}

// demoNet1 devices live on TEST-NET-2 (HQ), demoNet2 on TEST-NET-3 (branch).
var demoDevices = []demoDevice{
	{Name: "hq-core-sw01", IP: "198.51.100.1", MAC: "02:00:00:00:01:01", Type: "switch", Brand: "Cisco",
		Attrs: `{"inferred_type":"switch","inferred_type_source":"protocol","vendor":"Cisco","hostname":"hq-core-sw01","os":"IOS-XE 17.6"}`},
	{Name: "hq-gw", IP: "198.51.100.2", MAC: "02:00:00:00:01:02", Type: "router", Brand: "MikroTik",
		Attrs: `{"inferred_type":"router","inferred_type_source":"protocol","vendor":"MikroTik","hostname":"hq-gw","os":"RouterOS 7.14"}`},
	{Name: "hq-nas-01", IP: "198.51.100.10", MAC: "02:00:00:00:01:0a", Type: "nas", Brand: "Synology",
		Attrs: `{"inferred_type":"nas","inferred_type_source":"protocol","vendor":"Synology","hostname":"ds920-hq","os":"DSM 7.2"}`},
	{Name: "hq-cam-lobby", IP: "198.51.100.21", MAC: "02:00:00:00:01:15", Type: "camera", Brand: "Hikvision",
		Attrs: `{"inferred_type":"camera","inferred_type_source":"protocol","vendor":"Hikvision","hostname":"ipc-lobby","os":"V5.7.1"}`},
	{Name: "hq-cam-parking", IP: "198.51.100.22", MAC: "02:00:00:00:01:16", Type: "camera", Brand: "Hikvision",
		Attrs: `{"inferred_type":"camera","inferred_type_source":"protocol","vendor":"Hikvision","hostname":"ipc-parking","os":"V5.7.1"}`},
	{Name: "hq-ap-floor1", IP: "198.51.100.31", MAC: "02:00:00:00:01:1f", Type: "iot", Brand: "Ubiquiti",
		Attrs: `{"inferred_type":"iot","inferred_type_source":"protocol","vendor":"Ubiquiti","hostname":"u6-lite-f1","os":"UniFi 7.0"}`},
	{Name: "hq-ap-floor2", IP: "198.51.100.32", MAC: "02:00:00:00:01:20", Type: "iot", Brand: "Ubiquiti",
		Attrs: `{"inferred_type":"iot","inferred_type_source":"protocol","vendor":"Ubiquiti","hostname":"u6-lite-f2","os":"UniFi 7.0"}`},
	{Name: "hq-printer", IP: "198.51.100.41", MAC: "02:00:00:00:01:29", Type: "printer", Brand: "HP",
		Attrs: `{"inferred_type":"printer","inferred_type_source":"protocol","vendor":"HP","hostname":"NPI9A4B2C","os":""}`},
	{Name: "hq-vm-esxi", IP: "198.51.100.50", MAC: "02:00:00:00:01:32", Type: "server", Brand: "Dell",
		Attrs: `{"inferred_type":"server","inferred_type_source":"protocol","vendor":"Dell","hostname":"esxi-hq","os":"VMware ESXi 8.0"}`},
	{Name: "hq-nvr", IP: "198.51.100.23", MAC: "02:00:00:00:01:17", Type: "server", Brand: "Hikvision",
		Attrs: `{"inferred_type":"server","inferred_type_source":"protocol","vendor":"Hikvision","hostname":"nvr-hq"}`},
	{Name: "hq-tv-meeting", IP: "198.51.100.61", MAC: "02:00:00:00:01:3d", Type: "iot", Brand: "Xiaomi",
		Attrs: `{"inferred_type":"iot","inferred_type_source":"heuristic","vendor":"Xiaomi","hostname":"mi-tv-meeting"}`},
	{Name: "hq-sensor-door", IP: "198.51.100.62", MAC: "02:00:00:00:01:3e", Type: "iot", Brand: "Aqara",
		Attrs: `{"inferred_type":"iot","inferred_type_source":"heuristic","vendor":"Aqara","hostname":"door-sensor-1"}`},
	{Name: "hq-dev-mickey", IP: "198.51.100.70", MAC: "02:00:00:00:01:46", Type: "pc", Brand: "Apple",
		Attrs: `{"inferred_type":"pc","inferred_type_source":"heuristic","vendor":"Apple","hostname":"mickeys-mbp","os":"macOS 15"}`},
	{Name: "hq-dev-sara", IP: "198.51.100.71", MAC: "02:00:00:00:01:47", Type: "pc", Brand: "Lenovo",
		Attrs: `{"inferred_type":"pc","inferred_type_source":"heuristic","vendor":"Lenovo","hostname":"sara-thinkpad","os":"Windows 11"}`},
	{Name: "hq-phone-voip1", IP: "198.51.100.80", MAC: "02:00:00:00:01:50", Type: "phone", Brand: "Yealink",
		Attrs: `{"inferred_type":"phone","inferred_type_source":"protocol","vendor":"Yealink","hostname":"sip-101"}`},
	{Name: "br-gw", IP: "203.0.113.1", MAC: "02:00:00:00:02:01", Type: "router", Brand: "GL.iNet",
		Attrs: `{"inferred_type":"router","inferred_type_source":"protocol","vendor":"GL.iNet","hostname":"brume-branch","os":"OpenWrt 23.05"}`},
	{Name: "br-cam-gate", IP: "203.0.113.21", MAC: "02:00:00:00:02:15", Type: "camera", Brand: "Reolink",
		Attrs: `{"inferred_type":"camera","inferred_type_source":"protocol","vendor":"Reolink","hostname":"cam-gate"}`},
	{Name: "br-sw-managed", IP: "203.0.113.2", MAC: "02:00:00:00:02:02", Type: "switch", Brand: "TP-Link",
		Attrs: `{"inferred_type":"switch","inferred_type_source":"protocol","vendor":"TP-Link","hostname":"tl-sg-br"}`},
	{Name: "br-nas-offsite", IP: "203.0.113.10", MAC: "02:00:00:00:02:0a", Type: "nas", Brand: "QNAP",
		Attrs: `{"inferred_type":"nas","inferred_type_source":"protocol","vendor":"QNAP","hostname":"ts-462-br","os":"QTS 5.1"}`},
	{Name: "br-dev-kiosk", IP: "203.0.113.60", MAC: "02:00:00:00:02:3c", Type: "pc", Brand: "Raspberry Pi",
		Attrs: `{"inferred_type":"pc","inferred_type_source":"protocol","vendor":"Raspberry Pi Foundation","hostname":"kiosk-br","os":"Raspberry Pi OS"}`},
}

// Seed populates an empty database with the demo plane: 2 networks, ~20
// fictional devices, change history, probe targets with results, and a
// topology edge set. Idempotent-by-gate: callers only invoke it when
// IsDemoEmpty() reported true.
func Seed(ctx context.Context, dbConn *sql.DB, logger *slog.Logger) error {
	tx, err := dbConn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	exec := func(q string, args ...any) {
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			logger.Warn("demoseed: statement failed", "stmt", firstLine(q), "error", err)
		}
	}

	// Networks (TEST-NET documentation ranges — never routable in reality).
	exec(`INSERT INTO networks (name, cidr, site) VALUES ('demo-hq', '198.51.100.0/24', '演示·总部')`)
	exec(`INSERT INTO networks (name, cidr, site) VALUES ('demo-branch', '203.0.113.0/24', '演示·分支')`)
	var hqID, brID int64
	_ = tx.QueryRowContext(ctx, `SELECT id FROM networks WHERE name='demo-hq'`).Scan(&hqID)
	_ = tx.QueryRowContext(ctx, `SELECT id FROM networks WHERE name='demo-branch'`).Scan(&brID)

	// Devices: deterministic statuses (one offline for realism per network).
	for i, d := range demoDevices {
		netID := hqID
		if net.ParseIP(d.IP).To4()[0] == 203 {
			netID = brID
		}
		status := "online"
		if d.IP == "198.51.100.62" || d.IP == "203.0.113.60" { // door sensor + kiosk offline
			status = "offline"
		}
		du := fmt.Sprintf("demo-uuid-%04d", i+1)
		exec(`INSERT INTO devices (device_uuid, name, ip_address, mac_address, type, status, brand,
			network_id, scan_source, scan_attributes, first_seen, last_seen, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'scanner_v2', ?, ?, ?, ?, ?)`,
			du, d.Name, d.IP, d.MAC, d.Type, status, d.Brand, netID, d.Attrs,
			now.Add(-72*time.Hour), now.Add(-2*time.Minute), now.Add(-72*time.Hour), now.Add(-2*time.Minute))
	}

	// Change history: additions 3 days ago + a lost + a recovered + a change.
	exec(`INSERT INTO change_log (network_id, change_type, entity_type, entity_id, before_data, after_data, detected_at)
		SELECT network_id, 'device_added', 'device', id, '', '{}', datetime('now', '-3 days') FROM devices`)
	exec(`INSERT INTO change_log (network_id, change_type, entity_type, entity_id, before_data, after_data, detected_at)
		SELECT network_id, 'device_lost', 'device', id, '', '{}', datetime('now', '-9 hours') FROM devices WHERE name='hq-sensor-door'`)
	exec(`INSERT INTO change_log (network_id, change_type, entity_type, entity_id, before_data, after_data, detected_at)
		SELECT network_id, 'device_recovered', 'device', id, '', '{}', datetime('now', '-35 minutes') FROM devices WHERE name='hq-cam-parking'`)
	exec(`INSERT INTO change_log (network_id, change_type, entity_type, entity_id, before_data, after_data, detected_at)
		SELECT network_id, 'device_changed', 'device', id, '{"os":"V5.6.9"}', '{"os":"V5.7.1"}', datetime('now', '-2 hours') FROM devices WHERE name='hq-cam-lobby'`)

	// Probe targets (external synthetic probes) + recent results.
	exec(`INSERT INTO probe_targets (name, module, target, interval_seconds, timeout_seconds, enabled, created_at, updated_at)
		VALUES ('demo-portal', 'http', 'https://example.org', 60, 10, 1, datetime('now'), datetime('now'))`)
	exec(`INSERT INTO probe_targets (name, module, target, interval_seconds, timeout_seconds, enabled, created_at, updated_at)
		VALUES ('demo-api', 'http', 'https://api.example.org/healthz', 60, 10, 1, datetime('now'), datetime('now'))`)
	exec(`INSERT INTO probe_targets (name, module, target, interval_seconds, timeout_seconds, enabled, created_at, updated_at)
		VALUES ('demo-dns', 'tcp', '1.1.1.1:53', 60, 5, 1, datetime('now'), datetime('now'))`)
	rows, err := tx.QueryContext(ctx, `SELECT id FROM probe_targets`)
	if err == nil {
		var ids []int64
		for rows.Next() {
			var id int64
			_ = rows.Scan(&id)
			ids = append(ids, id)
		}
		rows.Close()
		for _, id := range ids {
			// 30 recent results, mostly success with a short outage window.
			for k := 29; k >= 0; k-- {
				status := "success"
				errMsg := ""
				if k >= 12 && k <= 13 { // a 2-minute blip 12-13 minutes ago
					status, errMsg = "fail", "dial timeout"
				}
				exec(`INSERT INTO probe_results (target_id, status, latency_ms, error_message, checked_at)
					VALUES (?, ?, ?, ?, datetime('now', ?))`,
					id, status, 8+rand.Intn(40), errMsg, fmt.Sprintf("-%d minutes", k))
			}
		}
	}

	// Topology: core switch ↔ gateway, plus switch ↔ a few endpoints.
	exec(`INSERT INTO topology_edges (from_device_id, to_device_id, edge_type, via_protocol, confidence, first_seen, last_seen)
		SELECT d1.id, d2.id, 'l2', 'LLDP', 0.95, datetime('now','-3 days'), datetime('now')
		FROM devices d1, devices d2 WHERE d1.name='hq-core-sw01' AND d2.name='hq-gw'`)
	exec(`INSERT INTO topology_edges (from_device_id, to_device_id, edge_type, via_protocol, confidence, first_seen, last_seen)
		SELECT d1.id, d2.id, 'l2', 'LLDP', 0.9, datetime('now','-3 days'), datetime('now')
		FROM devices d1, devices d2 WHERE d1.name='hq-core-sw01' AND d2.name IN ('hq-nas-01','hq-nvr','hq-vm-esxi')`)

	if err := tx.Commit(); err != nil {
		return err
	}
	logger.Info("demo seed applied", "devices", len(demoDevices), "networks", 2)
	return nil
}

// Activity keeps the demo dashboard alive: every tick one random online device
// flips offline→online or online→offline (with a matching change_log row), so
// the change stream and status widgets move without a real network.
type Activity struct {
	dbConn   *sql.DB
	logger   *slog.Logger
	interval time.Duration
	cancel   context.CancelFunc
	done     chan struct{}
}

// StartActivity launches the demo activity ticker (default every 45s).
func StartActivity(dbConn *sql.DB, logger *slog.Logger) *Activity {
	a := &Activity{dbConn: dbConn, logger: logger, interval: 45 * time.Second, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	go func() {
		defer close(a.done)
		t := time.NewTicker(a.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.tick(ctx)
			}
		}
	}()
	return a
}

// Stop halts the ticker.
func (a *Activity) Stop() {
	if a.cancel != nil {
		a.cancel()
	}
	<-a.done
}

func (a *Activity) tick(ctx context.Context) {
	// Pick one online device, flip it offline, log device_lost; next tick may
	// pick it back up (or another). Bounded churn keeps the demo honest.
	var id int64
	var name string
	err := a.dbConn.QueryRowContext(ctx,
		`SELECT id, name FROM devices WHERE status='online' AND name LIKE 'demo-%' ORDER BY RANDOM() LIMIT 1`).Scan(&id, &name)
	if err != nil {
		return
	}
	newStatus := "offline"
	changeType := "device_lost"
	// 70% chance to instead recover the offline one (keeps inventory mostly online).
	if rand.Intn(10) < 7 {
		if err := a.dbConn.QueryRowContext(ctx,
			`SELECT id FROM devices WHERE status='offline' AND name LIKE 'demo-%' LIMIT 1`).Scan(&id); err == nil {
			newStatus, changeType = "online", "device_recovered"
		}
	}
	if _, err := a.dbConn.ExecContext(ctx,
		`UPDATE devices SET status=?, updated_at=datetime('now') WHERE id=?`, newStatus, id); err != nil {
		return
	}
	var netID sql.NullInt64
	_ = a.dbConn.QueryRowContext(ctx, `SELECT network_id FROM devices WHERE id=?`, id).Scan(&netID)
	_, _ = a.dbConn.ExecContext(ctx,
		`INSERT INTO change_log (network_id, change_type, entity_type, entity_id, before_data, after_data, detected_at)
		 VALUES (?, ?, 'device', ?, '', '{}', datetime('now'))`, netID, changeType, id)
	a.logger.Debug("demo activity", "device", name, "status", newStatus)
}

// Wipe removes ALL demo-marked data (networks named demo-*, devices with
// demo-uuid-*). The route to a real deployment: clear the fiction, keep the
// binary running against a real subnet.
func Wipe(ctx context.Context, dbConn *sql.DB) error {
	tx, err := dbConn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range []string{
		`DELETE FROM probe_results WHERE target_id IN (SELECT id FROM probe_targets WHERE name LIKE 'demo-%')`,
		`DELETE FROM probe_targets WHERE name LIKE 'demo-%'`,
		`DELETE FROM change_log WHERE network_id IN (SELECT id FROM networks WHERE name LIKE 'demo-%')`,
		`DELETE FROM topology_edges WHERE from_device_id IN (SELECT id FROM devices WHERE device_uuid LIKE 'demo-uuid-%')`,
		`DELETE FROM heartbeat_configs WHERE device_id IN (SELECT id FROM devices WHERE device_uuid LIKE 'demo-uuid-%')`,
		`DELETE FROM devices WHERE device_uuid LIKE 'demo-uuid-%'`,
		`DELETE FROM networks WHERE name LIKE 'demo-%'`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// CountJSON is a tiny helper for the status endpoint payload.
func CountJSON(n int) []byte {
	b, _ := json.Marshal(map[string]int{"demo_devices": n})
	return b
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}
