// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package runner

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"time"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
)

// DetectLost runs the device_lost detection for one scan's outcome on one
// network. It is the post-scan set-difference:
//
//  1. For every alive host in `reports` on `networkID`: upsert its snapshot
//     (reset miss_count to 0, refresh last_seen_at).
//  2. For every snapshot on that network whose IP did NOT appear in the alive
//     set: increment its miss_count.
//  3. Emit device_lost + mark status='offline' for snapshots whose miss_count
//     has crossed the threshold AND whose device is still online.
//
// The threshold is the runner's lostThreshold (scanner.lost_threshold config
// key, default 2). Single missed scans (ICMP drop, brief host downtime, network
// jitter) must not flap a device offline — see architecture-future.md §8 note 3
// (去抖动/grace period).
//
// agentID threads through to change_log provenance (empty on the local-scan
// path). taskID is the scan that produced these reports (0/nil for agent
// reports). Safe to call when changeRecorder is nil (no-op for lost emission;
// the snapshot bookkeeping still runs so miss counts stay accurate).
//
// This is shared by the local scan path (runner.Run) and the agent→center
// ingestion path (AgentReportHandler.Report), so both get the same lost
// detection with the same grace period.
func (rn *Runner) DetectLost(ctx context.Context, networkID sql.NullInt64, taskID int64, reports []scannerv2.HostReport, agentID string) {
	if !networkID.Valid {
		// No network scoping (legacy/agent unresolved) — can't partition the
		// alive set, so lost detection is meaningless. Skip rather than risk
		// marking every device lost.
		return
	}
	netID := networkID.Int64

	// 1. Upsert snapshots for alive hosts (resets miss_count, refreshes
	//    last_seen_at) and build the alive IP set for the set difference.
	aliveIPs := rn.RecordAliveSnapshots(ctx, networkID, taskID, reports)

	// 2. Increment miss_count for snapshots NOT in the alive set — a single
	// batch UPDATE replaces the previous one-UPDATE-per-missing-host loop
	// (200 missing hosts = 200 individual UPDATEs → now 1). (#162)
	if err := rn.batchIncrementMiss(ctx, netID, aliveIPs); err != nil {
		rn.logger.Warn("detect-lost: batch increment miss failed", "network_id", netID, "error", err)
	}

	// 3. Emit device_lost for snapshots past the threshold that are still online.
	threshold := rn.LostThreshold()
	lost, err := rn.queries.ListLostSnapshots(ctx, db.ListLostSnapshotsParams{
		NetworkID: netID,
		MissCount: threshold,
	})
	if err != nil {
		rn.logger.Warn("detect-lost: list lost snapshots failed", "network_id", netID, "error", err)
		return
	}
	if len(lost) == 0 {
		return
	}
	now := time.Now().UTC()
	nid := netID
	var nidPtr *int64
	{
		v := nid
		nidPtr = &v
	}
	for _, l := range lost {
		// Mark the device offline (scan-side lost; heartbeat has its own
		// separate grace period for probe failures). Stamp offline_since so the
		// silent-device retention sweep has the "how long gone" signal (issue
		// #117). CASE guards so a device already offline keeps its original
		// offline_since (the flip time, not re-stamped every lost-detection pass).
		// Best-effort — a status write failure doesn't block the change_log emit.
		if _, err := rn.dbConn.ExecContext(ctx,
			`UPDATE devices SET status='offline',
				offline_since = CASE WHEN status != 'offline' THEN ? ELSE offline_since END,
				updated_at=? WHERE id=?`, scannerv2.DBTime(now), scannerv2.DBTime(now), l.DeviceID); err != nil {
			rn.logger.Warn("detect-lost: mark offline failed", "device_id", l.DeviceID, "error", err)
		}
		// Emit device_lost (before_data = the device's pre-lost snapshot).
		rn.recordDeviceLost(ctx, l.DeviceID, nidPtr, agentID)
		// Sample the offline verdict to the liveness series immediately (the
		// heartbeat tick would sample it too, but sampling here avoids a window
		// gap right at the transition the change engine judges on).
		if rn.heartbeat != nil {
			rn.heartbeat.SampleLiveness(l.DeviceID, "offline", "scan")
		}
	}
	if rn.logger != nil {
		slog.Info("detect-lost: devices declared lost",
			"network_id", netID, "count", len(lost), "threshold", threshold)
	}
}

// batchIncrementMiss bumps miss_count for every snapshot in the network whose
// IP is NOT in the alive set, in a single UPDATE. This replaces the previous
// per-snapshot IncrementSnapshotMiss loop (N missing hosts = N individual
// UPDATEs → now 1 query). (#162)
func (rn *Runner) batchIncrementMiss(ctx context.Context, netID int64, aliveIPs map[string]bool) error {
	if len(aliveIPs) == 0 {
		// No alive hosts at all — every snapshot in the network is missing.
		_, err := rn.dbConn.ExecContext(ctx,
			`UPDATE scan_snapshots SET miss_count = miss_count + 1 WHERE network_id = ?`, netID)
		return err
	}
	// Build NOT IN (?,...) with one placeholder per alive IP. The scan target
	// size is bounded (sync API rejects >1024 IPs), so the parameter count is
	// always well within SQLite's limit.
	placeholders := make([]string, 0, len(aliveIPs))
	args := make([]any, 0, len(aliveIPs)+1)
	args = append(args, netID)
	for ip := range aliveIPs {
		placeholders = append(placeholders, "?")
		args = append(args, ip)
	}
	query := `UPDATE scan_snapshots SET miss_count = miss_count + 1 ` +
		`WHERE network_id = ? AND ip NOT IN (` + strings.Join(placeholders, ",") + `)`
	_, err := rn.dbConn.ExecContext(ctx, query, args...)
	return err
}

// RecordAliveSnapshots upserts a scan snapshot for every alive host in reports
// (resets miss_count to 0, refreshes last_seen_at) and returns the set of alive
// IPs for the caller's set-difference. It is step 1 of DetectLost, extracted so
// the agent-report ingestion path can refresh leases WITHOUT running the
// expensive O(whole-network) miss-counting + lost-emission that DetectLost does.
//
// On the agent→center path the handler calls this directly (cheap: one indexed
// upsert per alive host) and defers lost detection to the background lease
// sweeper (lease_sweeper.go). The local-scan path still calls DetectLost, which
// internally delegates here for step 1.
//
// Returns nil (no-op) when networkID is invalid — mirrors DetectLost's guard.
func (rn *Runner) RecordAliveSnapshots(ctx context.Context, networkID sql.NullInt64, taskID int64, reports []scannerv2.HostReport) map[string]bool {
	aliveIPs := make(map[string]bool, len(reports))
	if !networkID.Valid {
		return aliveIPs
	}
	now := time.Now().UTC()
	for _, rep := range reports {
		if !rep.Alive || rep.IP == "" {
			continue
		}
		aliveIPs[rep.IP] = true
		mac := reportMAC(rep)
		var taskIDPtr *int64
		if taskID > 0 {
			t := taskID
			taskIDPtr = &t
		}
		// Resolve the device's stable uuid so the snapshot row follows the device,
		// not the IP. DetectLost runs AFTER applyDeviceBridge persisted the device
		// (Run step 3 → step 3c), so the device row exists on the local-scan path;
		// on the agent→center lease path a prior report already created it. An empty
		// uuid (device somehow still absent) is healed on the next scan.
		devUUID := rn.resolveDeviceUUIDForIP(ctx, rep.IP, networkID)
		if err := rn.upsertScanSnapshot(ctx, networkID.Int64, taskIDPtr, rep.IP, mac, devUUID, now); err != nil {
			rn.logger.Warn("record-alive-snapshots: upsert failed", "ip", rep.IP, "error", err)
		}
	}
	return aliveIPs
}

// recordDeviceLost emits a device_lost event (before_data = device snapshot,
// after_data nil — the device is now gone from the alive set). Re-reads the
// device for the before snapshot so before_data reflects its last-known state.
func (rn *Runner) recordDeviceLost(ctx context.Context, deviceID int64, networkID *int64, agentID string) {
	if rn.changeRecorder == nil {
		return
	}
	var before *changedetect.DeviceSnapshot
	if s := rn.snapshotDevice(ctx, deviceID); s != nil {
		before = s
	}
	rn.changeRecorder.Record(ctx, changedetect.ChangeEvent{
		ChangeType: changedetect.ChangeTypeDeviceLost,
		EntityType: changedetect.EntityTypeDevice,
		DeviceID:   deviceID,
		NetworkID:  networkID,
		AgentID:    agentID,
		Before:     before,
		After:      nil, // lost has no after
	})
}

// recordDeviceRecovered emits a device_recovered event — the symmetric
// counterpart of device_lost. A device previously declared lost (status=offline
// via DetectLost or the lease sweeper) has reappeared alive (status=online via a
// scan or a fresh lease). before_data = the offline snapshot (caller captures it
// BEFORE the online UPDATE, mirroring recoverFresh), after_data = the online
// snapshot. This replaces the old practice of reporting an offline→online flip
// as a generic device_changed, which buried real identity changes under status
// noise. Recovery is a liveness/topology event, not an identity change.
func (rn *Runner) recordDeviceRecovered(ctx context.Context, deviceID int64, networkID *int64, agentID string, before *changedetect.DeviceSnapshot) {
	if rn.changeRecorder == nil {
		return
	}
	var after *changedetect.DeviceSnapshot
	if s := rn.snapshotDevice(ctx, deviceID); s != nil {
		after = s
	}
	rn.changeRecorder.Record(ctx, changedetect.ChangeEvent{
		ChangeType: changedetect.ChangeTypeDeviceRecovered,
		EntityType: changedetect.EntityTypeDevice,
		DeviceID:   deviceID,
		NetworkID:  networkID,
		AgentID:    agentID,
		Before:     before,
		After:      after,
	})
}

// resolveDeviceUUIDForIP returns the stable device_uuid for an IP, scoped to
// networkID when valid (mirrors the store's resolveDeviceUUID identity rule).
// Returns "" on miss (the snapshot row gets device_uuid=” and is healed next
// scan). Used by RecordAliveSnapshots so a scan_snapshots lease row keys on the
// device's stable identity rather than its roaming-prone IP.
func (rn *Runner) resolveDeviceUUIDForIP(ctx context.Context, ip string, networkID sql.NullInt64) string {
	if rn.dbConn == nil {
		return ""
	}
	var u string
	var err error
	if networkID.Valid {
		err = rn.dbConn.QueryRowContext(ctx,
			`SELECT device_uuid FROM devices WHERE ip_address = ? AND network_id = ? LIMIT 1`,
			ip, networkID.Int64).Scan(&u)
		if err != nil {
			// Fall back to any device with this IP (NULL-network / cross-network).
			err = rn.dbConn.QueryRowContext(ctx,
				`SELECT device_uuid FROM devices WHERE ip_address = ? LIMIT 1`, ip).Scan(&u)
		}
	} else {
		err = rn.dbConn.QueryRowContext(ctx,
			`SELECT device_uuid FROM devices WHERE ip_address = ? LIMIT 1`, ip).Scan(&u)
	}
	if err != nil {
		return ""
	}
	return u
}

// upsertScanSnapshotRawSQL is the device_uuid-writing scan-snapshot upsert,
// implemented as raw SQL because sqlc's SQLite parser truncates the trailing
// bytes of the ON CONFLICT DO UPDATE clause when it contains a CASE WHEN on
// excluded.device_uuid (the same documented parser bug that forced
// ListStaleAgentSnapshots to raw SQL in lease_sweeper.go). The query is
// otherwise identical to the sqlc UpsertScanSnapshot, plus the device_uuid
// write + the CASE that preserves an existing uuid when the caller passes ”.
//
// CONFLICT target stays (network_id, ip): a DHCP roam (same network, new IP)
// inserts a fresh row with miss_count 0, and lost detection + the lease sweeper
// join through devices to follow the device by uuid, so the IP-keyed conflict
// target is the correct choice here.
func (rn *Runner) upsertScanSnapshot(ctx context.Context, networkID int64, taskID *int64, ip, mac, devUUID string, lastSeen time.Time) error {
	if rn.dbConn == nil {
		return nil
	}
	_, err := rn.dbConn.ExecContext(ctx, `
		INSERT INTO scan_snapshots (network_id, task_id, ip, mac, device_uuid, miss_count, last_seen_at)
		VALUES (?, ?, ?, ?, ?, 0, ?)
		ON CONFLICT(network_id, ip) DO UPDATE SET
			task_id = excluded.task_id,
			mac = CASE WHEN excluded.mac != '' THEN excluded.mac ELSE scan_snapshots.mac END,
			device_uuid = CASE WHEN excluded.device_uuid != '' THEN excluded.device_uuid ELSE scan_snapshots.device_uuid END,
			miss_count = 0,
			last_seen_at = excluded.last_seen_at`,
		networkID, taskID, ip, mac, devUUID, lastSeen)
	return err
}
