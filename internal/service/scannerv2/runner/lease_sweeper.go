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
	"time"

	"mibee-steward/internal/changedetect"
)

// staleAgentSnapshot is one row from either the stale- or recoverable-snapshot
// query (lease sweeper). The same shape serves both directions: a snapshot that
// is stale + online (→ mark offline) and a snapshot that is fresh + offline
// (→ recover online) carry the same columns.
type staleAgentSnapshot struct {
	ID         int64
	NetworkID  int64
	IP         string
	Mac        string
	LastSeenAt time.Time
	DeviceID   int64
}

// staleAgentSnapshotsSQL selects snapshots in agent-managed networks whose
// last_seen_at is older than the cutoff AND whose device is still online. The
// center's lease sweeper declares these devices lost: an agent that stops
// reporting a host (device left, agent down, network split) lets its snapshot
// go stale; once past the TTL the host is presumed gone. Only agent networks
// are swept — the center's own network is handled by the local-scan DetectLost
// path + the heartbeat service. The device JOIN + status='online' filter
// mirrors ListLostSnapshots so an already-lost device is not re-emitted.
//
// Defined as raw SQL (not sqlc) because sqlc's SQLite parser truncates this
// query's trailing bytes — see the NOTE in db/queries/scan_snapshots.sql.
const staleAgentSnapshotsSQL = `SELECT s.id, s.network_id, s.ip, s.mac, s.last_seen_at, d.id
FROM scan_snapshots s
JOIN devices d ON d.ip_address = s.ip AND (d.network_id = s.network_id OR d.network_id IS NULL)
JOIN networks n ON n.id = s.network_id
WHERE n.agent_id IS NOT NULL AND n.agent_id != ''
  AND s.last_seen_at < ?
  AND d.status = 'online'`

// recoverableAgentSnapshotsSQL is the symmetric inverse of staleAgentSnapshotsSQL:
// snapshots in agent-managed networks whose lease is FRESH (last_seen within the
// TTL window) but whose devices row is still 'offline'. This happens when the
// agent network is stable (the agent's state hash matches → the center takes the
// anti-entropy fast path in handler/agent_report.go, which only refreshes leases
// and never touches the devices table). A device the sweeper marked offline
// during a prior brief outage then stays offline forever on that fast path, even
// though the agent is actively reporting it alive again. This query finds those
// stuck rows so sweepOnce can flip them back to online — closing the recovery
// gap the stable-hash optimization opened. Same agent-only scope; the center's
// own network recovers online via its own applyDeviceBridge scan path.
const recoverableAgentSnapshotsSQL = `SELECT s.id, s.network_id, s.ip, s.mac, s.last_seen_at, d.id
FROM scan_snapshots s
JOIN devices d ON d.ip_address = s.ip AND (d.network_id = s.network_id OR d.network_id IS NULL)
JOIN networks n ON n.id = s.network_id
WHERE n.agent_id IS NOT NULL AND n.agent_id != ''
  AND s.last_seen_at >= ?
  AND d.status = 'offline'`

// LeaseSweeper is the background task that reconciles agent-managed device
// liveness against their scan_snapshots lease. It does BOTH directions in one
// pass:
//
//   - offline: a snapshot whose lease has gone stale (last_seen older than now -
//     ttl) while the device is still 'online' → the host is presumed gone; mark
//     it offline + emit device_lost.
//   - online (recovery): a snapshot whose lease is fresh (last_seen within the
//     ttl window) while the device is stuck 'offline' → the agent is actively
//     reporting it alive again, but the stable-hash fast path (agent_report.go)
//     never refreshed the devices row; flip it back online + emit device_changed.
//
// It replaces the per-report DetectLost call that used to run on every agent
// POST (O(whole network) each time): the agent ingestion path now only refreshes
// leases (RecordAliveSnapshots, one indexed upsert per alive host), and this
// sweeper — running on its own slow ticker — is the single place that declares
// agent devices lost AND the single place that recovers them, keeping the two
// directions symmetric against the same TTL.
//
// Scope: ONLY agent-managed networks (networks.agent_id non-empty). The
// center's own network keeps using the local-scan DetectLost path + the
// heartbeat service + applyDeviceBridge recovery; this sweeper never touches it
// (both queries filter on n.agent_id != ”).
//
// TTL semantics: a snapshot is stale when last_seen_at < now - ttl, fresh
// otherwise. With the agent's default 30s report cadence, a 5min TTL tolerates
// ~10 missed reports before a device is presumed gone — generous enough to
// absorb agent restarts and brief network splits without flapping.
type LeaseSweeper struct {
	runner   *Runner
	interval time.Duration // how often to sweep
	ttl      time.Duration // staleness threshold (last_seen older than now-ttl)
	logger   *slog.Logger
}

// NewLeaseSweeper constructs a sweeper. interval ≤0 → 60s, ttl ≤0 → 5min.
func NewLeaseSweeper(rn *Runner, interval, ttl time.Duration, logger *slog.Logger) *LeaseSweeper {
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &LeaseSweeper{runner: rn, interval: interval, ttl: ttl, logger: logger}
}

// Start launches the sweep loop. It returns immediately; the loop runs until
// ctx is cancelled. One sweep runs immediately on start so a center restart
// doesn't wait a full interval before reconciling stale agent devices.
func (s *LeaseSweeper) Start(ctx context.Context) {
	go func() {
		s.sweepOnce(ctx)
		t := time.NewTicker(s.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.sweepOnce(ctx)
			}
		}
	}()
}

// sweepOnce runs one reconciliation pass: it first expires agent devices whose
// lease has gone stale (online→offline), then recovers agent devices whose lease
// is fresh but whose row is stuck offline (offline→online). It is also the test
// entry point (Start launches a goroutine, which is awkward to drive
// deterministically).
func (s *LeaseSweeper) sweepOnce(ctx context.Context) {
	cutoff := time.Now().UTC().Add(-s.ttl)
	expired := s.expireStale(ctx, cutoff)
	recovered := s.recoverFresh(ctx, cutoff)
	if expired > 0 || recovered > 0 {
		s.logger.Info("lease sweeper: reconciliation pass",
			"expired", expired, "recovered", recovered,
			"ttl", s.ttl, "cutoff", cutoff.Format(time.RFC3339))
	}
}

// expireStale marks agent devices offline when their snapshot lease is older than
// the cutoff. Returns the number of devices expired.
func (s *LeaseSweeper) expireStale(ctx context.Context, cutoff time.Time) int {
	stale := s.querySnapshots(ctx, staleAgentSnapshotsSQL, cutoff, "list stale")
	if len(stale) == 0 {
		return 0
	}
	now := time.Now().UTC()
	for _, l := range stale {
		nid := l.NetworkID
		nidPtr := &nid
		// Mark the device offline (same best-effort UPDATE DetectLost uses).
		if _, err := s.runner.dbConn.ExecContext(ctx,
			`UPDATE devices SET status='offline', updated_at=? WHERE id=?`, now, l.DeviceID); err != nil {
			s.logger.Warn("lease sweeper: mark offline failed", "device_id", l.DeviceID, "ip", l.IP, "error", err)
		}
		// Emit device_lost (change_log + Watcher). No-op when changeRecorder
		// is nil (agent mode — but the sweeper only runs on the center anyway).
		s.runner.recordDeviceLost(ctx, l.DeviceID, nidPtr, "lease")
	}
	return len(stale)
}

// recoverFresh marks agent devices back online when their snapshot lease is
// within the TTL window but their devices row is stuck 'offline'. This closes
// the recovery gap the stable-hash fast path (agent_report.go) opens: on a
// stable network the fast path only refreshes leases and never touches the
// devices table, so a device the sweeper previously marked offline would stay
// offline indefinitely even as the agent actively reports it alive. The UPDATE
// mirrors applyDeviceBridge's online write (status + last_seen +
// last_scanned_at + updated_at). A device_changed event is emitted for each
// recovery (status is a tracked Diff field → before=offline/after=online),
// symmetric with how the scan path reports recovery. Returns the count
// recovered.
func (s *LeaseSweeper) recoverFresh(ctx context.Context, cutoff time.Time) int {
	recoverable := s.querySnapshots(ctx, recoverableAgentSnapshotsSQL, cutoff, "list recoverable")
	if len(recoverable) == 0 {
		return 0
	}
	now := time.Now().UTC()
	for _, l := range recoverable {
		// Capture the BEFORE snapshot while the row is still 'offline' so the
		// device_changed event's before_data is faithful (recordDeviceLost has
		// the opposite bug — it reads after the UPDATE).
		before := s.runner.snapshotDevice(ctx, l.DeviceID)
		if _, err := s.runner.dbConn.ExecContext(ctx,
			`UPDATE devices SET status='online', last_seen=?, last_scanned_at=?, updated_at=? WHERE id=?`,
			now, now, now, l.DeviceID); err != nil {
			s.logger.Warn("lease sweeper: recover online failed", "device_id", l.DeviceID, "ip", l.IP, "error", err)
			continue
		}
		// Emit device_changed only when the status actually flipped — a no-op
		// recovery (race: row flipped online between query and UPDATE) must not
		// emit noise. No-op when changeRecorder is nil.
		if before != nil {
			if after := s.runner.snapshotDevice(ctx, l.DeviceID); after != nil {
				if diff := changedetect.Diff(*before, *after); diff != nil {
					nid := sql.NullInt64{Int64: l.NetworkID, Valid: true}
					s.runner.recordDeviceChanged(ctx, l.DeviceID, nid, "lease", *before, *after, diff)
				}
			}
		}
	}
	return len(recoverable)
}

// querySnapshots runs one of the lease-sweeper SELECTs (stale or recoverable)
// and returns the matched rows. failLabel tags the warn log on error. Centralized
// so both directions share identical row-scanning + error handling.
func (s *LeaseSweeper) querySnapshots(ctx context.Context, query string, cutoff time.Time, failLabel string) []staleAgentSnapshot {
	rows, err := s.runner.dbConn.QueryContext(ctx, query, cutoff)
	if err != nil {
		s.logger.Warn("lease sweeper: "+failLabel+" failed", "error", err)
		return nil
	}
	var out []staleAgentSnapshot
	for rows.Next() {
		var r staleAgentSnapshot
		if err := rows.Scan(&r.ID, &r.NetworkID, &r.IP, &r.Mac, &r.LastSeenAt, &r.DeviceID); err != nil {
			rows.Close()
			s.logger.Warn("lease sweeper: scan failed", "error", err)
			return nil
		}
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.logger.Warn("lease sweeper: rows error", "error", err)
		return nil
	}
	return out
}
