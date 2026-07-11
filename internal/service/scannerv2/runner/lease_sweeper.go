package runner

import (
	"context"
	"log/slog"
	"time"
)

// staleAgentSnapshot is one row from the stale-snapshot query (lease sweeper).
type staleAgentSnapshot struct {
	ID         int64
	NetworkID  int64
	Ip         string
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

// LeaseSweeper is the background task that expires agent-managed devices whose
// snapshots have gone stale. It replaces the per-report DetectLost call that
// used to run on every agent POST (O(whole network) each time): the agent
// ingestion path now only refreshes leases (RecordAliveSnapshots, one indexed
// upsert per alive host), and this sweeper — running on its own slow ticker —
// is the single place that declares agent devices lost.
//
// Scope: ONLY agent-managed networks (networks.agent_id non-empty). The
// center's own network keeps using the local-scan DetectLost path + the
// heartbeat service; this sweeper never touches it (the query filters on
// n.agent_id != '').
//
// TTL semantics: a snapshot is stale when last_seen_at < now - ttl. With the
// agent's default 30s report cadence, a 5min TTL tolerates ~10 missed reports
// before a device is presumed gone — generous enough to absorb agent restarts
// and brief network splits without flapping.
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

// sweepOnce runs one expiration pass. It is also the test entry point
// (Start launches a goroutine, which is awkward to drive deterministically).
func (s *LeaseSweeper) sweepOnce(ctx context.Context) {
	cutoff := time.Now().UTC().Add(-s.ttl)
	rows, err := s.runner.dbConn.QueryContext(ctx, staleAgentSnapshotsSQL, cutoff)
	if err != nil {
		s.logger.Warn("lease sweeper: list stale failed", "error", err)
		return
	}
	var stale []staleAgentSnapshot
	for rows.Next() {
		var r staleAgentSnapshot
		if err := rows.Scan(&r.ID, &r.NetworkID, &r.Ip, &r.Mac, &r.LastSeenAt, &r.DeviceID); err != nil {
			rows.Close()
			s.logger.Warn("lease sweeper: scan failed", "error", err)
			return
		}
		stale = append(stale, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.logger.Warn("lease sweeper: rows error", "error", err)
		return
	}
	if len(stale) == 0 {
		return
	}
	now := time.Now().UTC()
	for _, l := range stale {
		nid := l.NetworkID
		nidPtr := &nid
		// Mark the device offline (same best-effort UPDATE DetectLost uses).
		if _, err := s.runner.dbConn.ExecContext(ctx,
			`UPDATE devices SET status='offline', updated_at=? WHERE id=?`, now, l.DeviceID); err != nil {
			s.logger.Warn("lease sweeper: mark offline failed", "device_id", l.DeviceID, "ip", l.Ip, "error", err)
		}
		// Emit device_lost (change_log + Watcher). No-op when changeRecorder
		// is nil (agent mode — but the sweeper only runs on the center anyway).
		s.runner.recordDeviceLost(ctx, l.DeviceID, nidPtr, "lease")
	}
	s.logger.Info("lease sweeper: devices expired",
		"count", len(stale), "ttl", s.ttl, "cutoff", cutoff.Format(time.RFC3339))
}
