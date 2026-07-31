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
	FlapCount  int64
	LastFlapAt sql.NullTime
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
// The device JOIN is device_uuid-aware: when the snapshot row carries a uuid we
// match the device by (device_uuid, network_id), which means a device that
// DHCP-roamed to a new IP is STILL found from its stale pre-roam snapshot row
// (the device's uuid is unchanged across the roam) — so a roam can't strand a
// device's lease on the old IP. Transition rows with empty device_uuid fall back
// to the IP join.
//
// Defined as raw SQL (not sqlc) because sqlc's SQLite parser truncates this
// query's trailing bytes — see the NOTE in db/queries/scan_snapshots.sql.
const staleAgentSnapshotsSQL = `SELECT s.id, s.network_id, s.ip, s.mac, s.last_seen_at, d.id, s.flap_count, s.last_flap_at
FROM scan_snapshots s
JOIN devices d ON (
	(s.device_uuid != '' AND d.device_uuid = s.device_uuid AND d.network_id = s.network_id)
	OR (s.device_uuid = '' AND d.ip_address = s.ip AND (d.network_id = s.network_id OR d.network_id IS NULL))
)
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
// own network recovers online via its own applyDeviceBridge scan path. The
// device_uuid-aware JOIN matches staleAgentSnapshotsSQL.
const recoverableAgentSnapshotsSQL = `SELECT s.id, s.network_id, s.ip, s.mac, s.last_seen_at, d.id, s.flap_count, s.last_flap_at
FROM scan_snapshots s
JOIN devices d ON (
	(s.device_uuid != '' AND d.device_uuid = s.device_uuid AND d.network_id = s.network_id)
	OR (s.device_uuid = '' AND d.ip_address = s.ip AND (d.network_id = s.network_id OR d.network_id IS NULL))
)
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

// Flap-debounce constants for the lease sweeper. An agent device that bounces
// online/offline (a flaky-WiFi IoT device the agent sees intermittently) would
// otherwise emit a device_lost/device_recovered storm. Once a device has crossed
// flapThreshold liveness transitions, further transitions update devices.status
// but do NOT emit change_log events — the device is recognized as flapping. The
// counter DECAYS (halves) once a stable window (flapStablePeriod) passes with no
// flap, so a device that genuinely stops bouncing earns its way back to normal
// event recording across a few stable periods; a periodic device that keeps
// bouncing never clears the counter and stays suppressed.
const (
	flapThreshold    = int64(4)         // transitions before a device is considered flapping
	flapStablePeriod = 30 * time.Minute // how long quiet before a decay pass halves flap_count
)

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
//
// Flap debouncing: a device whose flap_count has crossed flapThreshold is
// recognized as flapping — its status is still updated (so the registry reflects
// current liveness) but NO device_lost event is emitted, stopping the lost storm
// an intermittently-seen IoT device would otherwise generate. Each transition
// increments flap_count; recoverFresh DECAYS it (halves, not resets) after a
// stable-online window so a periodic device can't clear its counter on every
// cycle (see recoverFresh for the full rationale).
func (s *LeaseSweeper) expireStale(ctx context.Context, cutoff time.Time) int {
	stale := s.querySnapshots(ctx, staleAgentSnapshotsSQL, cutoff, "list stale")
	if len(stale) == 0 {
		return 0
	}
	now := time.Now().UTC()
	for _, l := range stale {
		// Increment flap_count + stamp last_flap_at for every transition (this
		// UPDATE is independent of whether we emit, so the flap counter advances
		// even while suppressed — keeping the "how flaky is this device" signal
		// accurate for the stable-period reset decision).
		if _, err := s.runner.dbConn.ExecContext(ctx,
			`UPDATE scan_snapshots SET flap_count = flap_count + 1, last_flap_at = ? WHERE id = ?`,
			now, l.ID); err != nil {
			s.logger.Warn("lease sweeper: flap_count increment failed", "snapshot_id", l.ID, "error", err)
		}
		// Mark the device offline (always — the registry must reflect liveness
		// regardless of event suppression). Stamp offline_since on the flip (CASE
		// guards so an already-offline device keeps its original stamp) for the
		// silent-device retention sweep (issue #117).
		if _, err := s.runner.dbConn.ExecContext(ctx,
			`UPDATE devices SET status='offline',
				offline_since = CASE WHEN status != 'offline' THEN ? ELSE offline_since END,
				updated_at=? WHERE id=?`, now, now, l.DeviceID); err != nil {
			s.logger.Warn("lease sweeper: mark offline failed", "device_id", l.DeviceID, "ip", l.IP, "error", err)
		}
		// Flap suppression: once past the threshold, stop emitting. The device is
		// known-unstable; recording every disappearance floods change_log. The
		// status column still tracks it for the device list / dashboard.
		flapping := l.FlapCount+1 >= flapThreshold // +1 for this transition
		if !flapping {
			nid := l.NetworkID
			s.runner.recordDeviceLost(ctx, l.DeviceID, &nid, "lease")
		}
		// Sample the offline verdict to the liveness series (always — the series
		// tracks actual liveness, independent of event suppression).
		if s.runner.heartbeat != nil {
			s.runner.heartbeat.SampleLiveness(l.DeviceID, "offline", "lease")
		}
	}
	return len(stale)
}

// recoverFresh marks agent devices back online when their snapshot lease is
// within the TTL window but their devices row is stuck 'offline'. This closes
// the recovery gap the stable-hash fast path (agent_report.go) opens.
//
// Flap debouncing mirrors expireStale: a flapping device's status is updated but
// no device_recovered event is emitted while its flap_count is at/above the
// threshold. The counter DECAYS (halves) once last_flap_at is older than
// flapStablePeriod — NOT a hard reset to 0. The decay-only design is deliberate:
// a hard reset let periodic WiFi-IoT devices (wake every ~35min > flapStablePeriod)
// clear their counter on every cycle and re-emit device_recovered forever,
// flooding change_log. With decay, a device must stay quiet across SEVERAL stable
// periods to return to normal event recording; a device that keeps bouncing
// never gives the counter room to clear, so it stays suppressed. See the inline
// state-machine comment in the loop body for the full rationale.
func (s *LeaseSweeper) recoverFresh(ctx context.Context, cutoff time.Time) int {
	recoverable := s.querySnapshots(ctx, recoverableAgentSnapshotsSQL, cutoff, "list recoverable")
	if len(recoverable) == 0 {
		return 0
	}
	now := time.Now().UTC()
	for _, l := range recoverable {
		// Capture the BEFORE snapshot while the row is still 'offline'.
		before := s.runner.snapshotDevice(ctx, l.DeviceID)
		if _, err := s.runner.dbConn.ExecContext(ctx,
			`UPDATE devices SET status='online', last_seen=?, last_scanned_at=?, offline_since=NULL, updated_at=? WHERE id=?`,
			now, now, now, l.DeviceID); err != nil {
			s.logger.Warn("lease sweeper: recover online failed", "device_id", l.DeviceID, "ip", l.IP, "error", err)
			continue
		}
		// Flap-count maintenance. This is the debounce state machine's heart. The
		// goal: a device that genuinely stabilizes (stays continuously online) earns
		// its flap_count back down to 0; a device still bouncing must NOT reset,
		// because resetting lets it re-fire device_recovered on every cycle.
		//
		// The previous design reset to 0 whenever now-last_flap_at >= flapStablePeriod.
		// That was WRONG for a periodic device (a WiFi-IoT device that wakes every
		// ~35min): its last_flap_at is set by the *prior expire* ~35min ago, so every
		// recovery looked "stable" and reset the counter — the device never stayed
		// suppressed, and change_log filled with device_recovered storms.
		//
		// Correct semantics: "stable" means the device has been REPEATEDLY seen
		// online over a long window with no expiry in between. We can't observe
		// "continuously online" from a single sweep (the recover query only matches
		// while status='offline'), so we use DECAY instead of hard reset:
		//   - last_flap_at older than flapStablePeriod → halve flap_count (slow
		//     recovery; a device must stay quiet for several stable periods to clear).
		//   - otherwise (flap was recent) → increment (this recovery is another flap).
		// A device that truly stops flapping decays to 0 within a few stable periods
		// and resumes normal event recording. A periodic device that keeps bouncing
		// never gives the counter room to clear, so it stays suppressed.
		staleFlap := l.LastFlapAt.Valid && now.Sub(l.LastFlapAt.Time) >= flapStablePeriod
		var effectiveFlapCount int64
		if staleFlap {
			// Decay: halve the counter, refresh last_flap_at to now (start a new
			// stable window from this recovery).
			effectiveFlapCount = l.FlapCount / 2
			if _, err := s.runner.dbConn.ExecContext(ctx,
				`UPDATE scan_snapshots SET flap_count = ?, last_flap_at = ? WHERE id = ?`,
				effectiveFlapCount, now, l.ID); err != nil {
				s.logger.Warn("lease sweeper: flap_count decay failed", "snapshot_id", l.ID, "error", err)
			}
		} else {
			// Flap was recent (within the stable window) → this recovery is another
			// flap transition; increment and stamp last_flap_at.
			effectiveFlapCount = l.FlapCount + 1
			if _, err := s.runner.dbConn.ExecContext(ctx,
				`UPDATE scan_snapshots SET flap_count = ?, last_flap_at = ? WHERE id = ?`,
				effectiveFlapCount, now, l.ID); err != nil {
				s.logger.Warn("lease sweeper: flap_count increment failed", "snapshot_id", l.ID, "error", err)
			}
		}
		// Sample the online verdict to the liveness series (always).
		if s.runner.heartbeat != nil {
			s.runner.heartbeat.SampleLiveness(l.DeviceID, "online", "lease")
		}
		// Emit device_recovered only on a genuine offline→online flip AND when not
		// suppressed by flapping. A device that has decayed back below the threshold
		// (effectiveFlapCount < flapThreshold) DOES emit — it has earned back normal
		// event recording by staying quiet long enough. A still-flapping device
		// (effectiveFlapCount >= flapThreshold) is suppressed.
		if before != nil && before.Status == "offline" {
			flapping := effectiveFlapCount >= flapThreshold
			if !flapping {
				nid := l.NetworkID
				s.runner.recordDeviceRecovered(ctx, l.DeviceID, &nid, "lease", before)
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
		if err := rows.Scan(&r.ID, &r.NetworkID, &r.IP, &r.Mac, &r.LastSeenAt, &r.DeviceID, &r.FlapCount, &r.LastFlapAt); err != nil {
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
