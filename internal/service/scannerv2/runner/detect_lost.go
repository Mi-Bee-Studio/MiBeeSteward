package runner

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
)

// lostThreshold is the number of consecutive scans a device must be absent
// before being declared lost. Single missed scans (ICMP drop, brief host
// downtime, network jitter) must not flap a device offline — see
// architecture-future.md §8 note 3 (去抖动/grace period).
const lostThreshold = 2

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
	now := time.Now().UTC()

	// 1. Build the alive IP set + upsert snapshots for alive hosts.
	aliveIPs := make(map[string]bool, len(reports))
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
		if err := rn.queries.UpsertScanSnapshot(ctx, db.UpsertScanSnapshotParams{
			NetworkID:  netID,
			TaskID:     taskIDPtr,
			Ip:         rep.IP,
			Mac:        mac,
			LastSeenAt: now,
		}); err != nil {
			rn.logger.Warn("detect-lost: upsert snapshot failed", "ip", rep.IP, "error", err)
		}
	}

	// 2. Increment miss_count for snapshots NOT in the alive set.
	snaps, err := rn.queries.ListSnapshotsForNetwork(ctx, netID)
	if err != nil {
		rn.logger.Warn("detect-lost: list snapshots failed", "network_id", netID, "error", err)
		return
	}
	for _, s := range snaps {
		if aliveIPs[s.Ip] {
			continue // seen this scan — miss_count already reset by the upsert
		}
		if err := rn.queries.IncrementSnapshotMiss(ctx, s.ID); err != nil {
			rn.logger.Warn("detect-lost: increment miss failed", "snapshot_id", s.ID, "ip", s.Ip, "error", err)
		}
	}

	// 3. Emit device_lost for snapshots past the threshold that are still online.
	lost, err := rn.queries.ListLostSnapshots(ctx, db.ListLostSnapshotsParams{
		NetworkID: netID,
		MissCount: lostThreshold,
	})
	if err != nil {
		rn.logger.Warn("detect-lost: list lost snapshots failed", "network_id", netID, "error", err)
		return
	}
	if len(lost) == 0 {
		return
	}
	nid := netID
	var nidPtr *int64
	{
		v := nid
		nidPtr = &v
	}
	for _, l := range lost {
		// Mark the device offline (scan-side lost; heartbeat has its own
		// separate grace period for probe failures). Best-effort — a status
		// write failure doesn't block the change_log emit.
		if _, err := rn.dbConn.ExecContext(ctx,
			`UPDATE devices SET status='offline', updated_at=? WHERE id=?`, now, l.DeviceID); err != nil {
			rn.logger.Warn("detect-lost: mark offline failed", "device_id", l.DeviceID, "error", err)
		}
		// Emit device_lost (before_data = the device's pre-lost snapshot).
		rn.recordDeviceLost(ctx, l.DeviceID, nidPtr, agentID)
	}
	if rn.logger != nil {
		slog.Info("detect-lost: devices declared lost",
			"network_id", netID, "count", len(lost), "threshold", lostThreshold)
	}
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
