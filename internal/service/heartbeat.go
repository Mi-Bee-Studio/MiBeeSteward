package service

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/probe"
	"mibee-steward/internal/service/scannerv2"
)

// HeartbeatService manages heartbeat scheduling and result processing.
type HeartbeatService struct {
	queries      *db.Queries     // MAIN db — for config CRUD + status sync (NOT per-tick writes)
	mainDB       *sql.DB         // raw main DB conn (for initStatusCache + syncStatus batch writes)
	store        *HeartbeatStore // dedicated heartbeat_results store (separate file)
	cfg          config.HeartbeatConfig
	cancel       context.CancelFunc
	cancelMu     sync.Mutex    // guards cancel (written by Start, read by Stop)
	failCounts   map[int64]int // deviceID -> consecutive failure count
	failCountsMu sync.Mutex    // guards failCounts only
	// statusCache is the in-memory source of truth for device status during
	// probing. applyDeviceVerdict writes here (never to the DB); a separate
	// syncStatusLoop is the SOLE writer of devices.status to the main DB.
	// This eliminates the SQLite WAL read-isolation race that caused fleet-wide
	// online/offline flapping under concurrent probing.
	statusCache   map[int64]string // deviceID -> "online"/"offline"
	statusCacheMu sync.RWMutex     // RWMutex: many probe readers, sync writer
	// lastSynced tracks what syncStatusLoop last wrote to the DB, so it only
	// UPDATEs devices whose status actually changed (zero writes in steady state).
	lastSynced map[int64]string
	// lastProbe tracks the last probe time per config IN MEMORY. isDue reads
	// this instead of querying the (async, batched) heartbeat store.
	lastProbe   map[int64]time.Time // configID -> last probe time
	lastProbeMu sync.RWMutex
}

// NewHeartbeatService creates a new HeartbeatService. mainDB is the main CRUD
// connection (for device status writes); store is the dedicated heartbeat_results
// time-series store (separate SQLite file, batched writes).
func NewHeartbeatService(mainDB *sql.DB, store *HeartbeatStore, cfg *config.Config) *HeartbeatService {
	return &HeartbeatService{
		queries:     db.New(mainDB),
		mainDB:      mainDB,
		store:       store,
		cfg:         cfg.Heartbeat,
		failCounts:  make(map[int64]int),
		statusCache: make(map[int64]string),
		lastSynced:  make(map[int64]string),
		lastProbe:   make(map[int64]time.Time),
	}
}

// Store returns the dedicated heartbeat time-series store. Used by the retention
// sweeper (to prune heartbeat_results from the right DB) and by device-delete
// (to cascade-delete a device's heartbeat rows, replacing the FK that existed
// when the table lived in the main DB).
func (s *HeartbeatService) Store() *HeartbeatStore { return s.store }

// Start begins the heartbeat scheduler loop in the background.
func (s *HeartbeatService) Start(ctx context.Context) {
	// Bound the loop with a cancellable context; store the cancel func under
	// the mutex so Stop() (called from another goroutine) can read it safely.
	ctx, cancel := context.WithCancel(ctx)
	s.cancelMu.Lock()
	s.cancel = cancel
	s.cancelMu.Unlock()
	defer cancel()

	// Note: heartbeat_results pruning used to run once here on start. It now
	// lives in the unified retention sweeper (cleanup.Service), which covers
	// heartbeat_results plus every other detail table on a single periodic
	// ticker — so a long-running heartbeat loop no longer needs its own ad-hoc
	// cleanup and won't drift out of sync with the configured retention window.

	// Start the dedicated store's batched-write flush loop.
	s.store.Start(ctx)

	// Initialize statusCache from the DB so a restart doesn't lose state.
	s.initStatusCache(ctx)

	// Start the status sync loop — the SOLE writer of devices.status to the
	// main DB. Probes write to statusCache (memory); this loop syncs every 30s.
	go s.syncStatusLoop(ctx)

	// 30s ticker for probing. Probes write results to the store (separate DB)
	// and verdicts to statusCache (memory) — neither touches the main DB, so
	// concurrent probing is safe (no SQLite race).
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	slog.Info("heartbeat scheduler started")

	for {
		select {
		case <-ctx.Done():
			slog.Info("heartbeat scheduler stopped")
			return
		case <-ticker.C:
			s.runChecks(ctx)
		}
	}
}

// Stop cancels the scheduler context, does a final status sync, and closes the
// dedicated heartbeat store.
func (s *HeartbeatService) Stop() {
	s.cancelMu.Lock()
	cancel := s.cancel
	s.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
	// Final sync: flush in-memory status to the DB so a restart sees the right state.
	s.syncStatus(context.Background())
	if s.store != nil {
		if err := s.store.Close(); err != nil {
			slog.Error("heartbeat store close failed", "error", err)
		}
	}
}

// GetQueries returns the underlying sqlc queries for handler use.
func (s *HeartbeatService) GetQueries() *db.Queries {
	return s.queries
}

// CreateDefaultConfig creates a default ICMP heartbeat config for a device.
// target = device IP, method = icmp, interval = 30s, timeout = 5s, enabled = true.
func (s *HeartbeatService) CreateDefaultConfig(ctx context.Context, deviceID int64, target string) error {
	_, err := s.queries.CreateHeartbeatConfig(ctx, db.CreateHeartbeatConfigParams{
		DeviceID:        deviceID,
		Method:          "icmp",
		Target:          target,
		IntervalSeconds: 30,
		TimeoutSeconds:  5,
		SnmpCommunity:   "public",
		SnmpOid:         "1.3.6.1.2.1.1.3.0",
		Enabled:         1,
	})

	return err
}

// CreateConfigs creates multiple heartbeat configs for a device from v2 specs.
// Accepts scannerv2.HeartbeatSpec (the v2 engine's canonical heartbeat type),
// decoupling heartbeat from the legacy scanner package.
func (s *HeartbeatService) CreateConfigs(ctx context.Context, deviceID int64, configs []scannerv2.HeartbeatSpec) error {
	if len(configs) == 0 {
		return nil
	}
	validMethods := map[string]bool{"icmp": true, "snmp": true, "http": true, "tcp": true}
	for _, cfg := range configs {
		if !validMethods[cfg.Method] {
			return fmt.Errorf("invalid heartbeat method: %s", cfg.Method)
		}
		_, err := s.queries.CreateHeartbeatConfig(ctx, db.CreateHeartbeatConfigParams{
			DeviceID:        deviceID,
			Method:          cfg.Method,
			Target:          cfg.Target,
			IntervalSeconds: int64(cfg.IntervalSeconds),
			TimeoutSeconds:  int64(cfg.TimeoutSeconds),
			SnmpCommunity:   cfg.SNMPCommunity,
			SnmpOid:         cfg.SNMPOID,
			Enabled:         1,
		})
		if err != nil {
			return fmt.Errorf("create %s config for device %d: %w", cfg.Method, deviceID, err)
		}
	}
	return nil
}

// GetProber returns the appropriate Prober for the given method.
func GetProber(method, community, oid string) probe.Prober {
	switch method {
	case "icmp":
		return &probe.ICMPProber{}
	case "http":
		return &probe.HTTPProber{}
	case "tcp":
		return &probe.TCPProber{}
	case "snmp":
		return &probe.SNMPProber{
			Community: community,
			OID:       oid,
		}
	default:
		return &probe.ICMPProber{}
	}
}

// runChecks evaluates heartbeat status at the DEVICE level, not the config
// level. A device typically has multiple heartbeat configs (icmp + tcp + http,
// seeded by the scanner for each service it identified). The previous
// implementation called updateDeviceStatus once PER config, so whichever config
// ran last won the race — a single flapping service config dragged the whole
// device to "offline" even when icmp was perfectly healthy, and devices
// oscillated online/offline every tick. Any list snapshot then showed a large
// fraction "offline" purely by bad timing.
//
// The new model groups all due configs by device, runs them, and applies ONE
// aggregated decision per device per tick: any-success ⇒ online; all-fail ⇒
// advance a device-level failure counter, only transitioning to offline at the
// threshold.
func (s *HeartbeatService) runChecks(ctx context.Context) {
	configs, err := s.queries.ListEnabledConfigs(ctx)
	if err != nil {
		slog.Error("heartbeat error listing configs", "error", err)
		return
	}

	// Group configs by device. A device is probed this tick if ANY of its
	// configs is due — and when it's due, ALL its configs are probed together
	// (not just the due ones). This matters: a device typically has icmp+tcp+http
	// configs with the same interval but slightly staggered last-checked times,
	// so per-config isDue would sometimes include only the failing config in a
	// tick, making OR-aggregation see an all-fail that's really just one stale
	// config. Device-level due + probe-all-configs keeps the OR verdict honest.
	allByDevice := make(map[int64][]db.HeartbeatConfig)
	deviceDue := make(map[int64]bool)
	for _, cfg := range configs {
		allByDevice[cfg.DeviceID] = append(allByDevice[cfg.DeviceID], cfg)
		if !deviceDue[cfg.DeviceID] && s.isDue(ctx, cfg) {
			deviceDue[cfg.DeviceID] = true
		}
	}
	byDevice := make(map[int64][]db.HeartbeatConfig)
	for devID, cfgs := range allByDevice {
		if deviceDue[devID] {
			byDevice[devID] = cfgs
		}
	}

	// Probe devices CONCURRENTLY. The previous serial loop (one device after
	// another, each config retried 3× with backoff) made a single runChecks pass
	// take 2-3 minutes on ~84 devices — far longer than the 10s ticker, so ticks
	// were skipped and each config was effectively probed only every ~3 minutes
	// instead of its configured 30s interval. That desynchronized the per-config
	// timing and produced the very online/offline flapping this OR-aggregation
	// rewrite was meant to fix. A bounded worker pool keeps concurrency sane
	// (each probe already has its own timeout; we just don't want hundreds of
	// goroutines hammering the network at once).
	// Concurrent probing (16 workers). This is safe now: probes write results
	// to the heartbeat store (separate DB) and verdicts to statusCache (memory)
	// — neither touches the main DB's devices.status. The sole writer of
	// devices.status is syncStatusLoop (serial, every 30s).
	const maxConcurrency = 16
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	for deviceID, cfgs := range byDevice {
		wg.Add(1)
		go func(deviceID int64, cfgs []db.HeartbeatConfig) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			s.checkDevice(ctx, deviceID, cfgs)
		}(deviceID, cfgs)
	}
	wg.Wait()
}

// checkDevice runs every due config for one device, persists each result, and
// then applies the OR-aggregated verdict (any success ⇒ online) once.
//
// Configs WITHIN a device are probed SERIALLY (not concurrently). The previous
// concurrent version raced on the results slice under the probe pool, which
// caused intermittent all-fail verdicts for devices whose probes all succeeded
// — the root cause of the persistent fleet-wide online/offline flapping.
// Devices still run concurrently (maxConcurrency), so a fleet of 84 finishes in
// ~2 batches; serializing 1-3 quick probes per device adds negligible latency.
func (s *HeartbeatService) checkDevice(ctx context.Context, deviceID int64, cfgs []db.HeartbeatConfig) {
	anySuccess := false
	for _, cfg := range cfgs {
		if s.probeAndRecord(ctx, cfg) {
			anySuccess = true
		}
	}
	s.applyDeviceVerdict(deviceID, anySuccess)
}

// probeAndRecord runs a single config (with retry), writes the result row, and
// reports whether the probe succeeded.
func (s *HeartbeatService) probeAndRecord(ctx context.Context, cfg db.HeartbeatConfig) bool {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	prober := GetProber(cfg.Method, cfg.SnmpCommunity, cfg.SnmpOid)
	// 1 attempt (no retry). Heartbeat is continuous monitoring — a failed probe
	// retries naturally on the next tick. The previous 3-attempt retry made a
	// single unreachable-ICMP config take ~18s (3 × 5s timeout + backoff), which
	// blew past the ticker interval and desynchronized the whole fleet.
	prober = probe.NewRetryProber(prober, 1, 1*time.Second)
	// Mark this config as probed NOW (before the probe runs) so isDue won't
	// double-schedule it on the next tick even if this probe is slow.
	s.lastProbeMu.Lock()
	s.lastProbe[cfg.ID] = time.Now()
	s.lastProbeMu.Unlock()
	result, err := prober.Probe(ctx, cfg.Target, timeout)
	if err != nil {
		slog.Error("heartbeat probe error", "config_id", cfg.ID, "error", err)
		// A transport-level error counts as a failure for aggregation.
		return false
	}

	// Determine status
	status := "success"
	var latencyMs float64
	var errorMsg string

	if result.Success {
		latencyMs = float64(result.Latency.Microseconds()) / 1000.0
	} else {
		status = "fail"
		errorMsg = result.ErrorMessage
	}

	// Hand the result to the dedicated time-series store's batched writer.
	// Enqueue is non-blocking (drops on overflow with a warning); a dropped
	// history row never affects the status verdict, which is returned below
	// directly from the probe result.
	s.store.Enqueue(resultRow{
		DeviceID:     cfg.DeviceID,
		ConfigID:     cfg.ID,
		Status:       status,
		LatencyMs:    latencyMs,
		ErrorMessage: errorMsg,
		CheckedAt:    time.Now(),
	})

	return result.Success
}

// applyDeviceVerdict updates the IN-MEMORY status cache based on probe results.
// It does NOT touch the main DB — that's syncStatusLoop's job (sole writer).
// This eliminates the SQLite WAL read-isolation race that caused fleet-wide
// flapping when concurrent goroutines read+wrote devices.status.
func (s *HeartbeatService) applyDeviceVerdict(deviceID int64, anySuccess bool) {
	// Read current in-memory status (for change detection / logging).
	s.statusCacheMu.RLock()
	oldStatus := s.statusCache[deviceID]
	s.statusCacheMu.RUnlock()

	var newStatus string
	if anySuccess {
		s.failCountsMu.Lock()
		s.failCounts[deviceID] = 0
		s.failCountsMu.Unlock()
		newStatus = "online"
	} else {
		s.failCountsMu.Lock()
		s.failCounts[deviceID]++
		count := s.failCounts[deviceID]
		s.failCountsMu.Unlock()

		const offlineThreshold = 5
		if count < offlineThreshold {
			return // not yet at threshold, keep current status
		}
		newStatus = "offline"
	}

	// Only update if status actually changed (reduces sync work + alert noise).
	if newStatus != "" && newStatus != oldStatus {
		s.statusCacheMu.Lock()
		s.statusCache[deviceID] = newStatus
		s.statusCacheMu.Unlock()
		slog.Info("device status changed (memory)", "device_id", deviceID, "status", newStatus)
	}
}

// ResetFailures clears the in-memory device-level failure counter for a device.
// Called by the scanner's device bridge when a scan confirms the host is alive
// and sets status=online — otherwise a stale counter from a prior flapping
// window would trip the very next heartbeat tick back to offline.
func (s *HeartbeatService) ResetFailures(deviceID int64) {
	s.failCountsMu.Lock()
	if s.failCounts[deviceID] > 0 {
		s.failCounts[deviceID] = 0
	}
	s.failCountsMu.Unlock()
}

// cachedStatus returns the in-memory status for a device (for test assertions
// and internal reads that don't want to hit the DB / wait for sync).
func (s *HeartbeatService) cachedStatus(deviceID int64) string {
	s.statusCacheMu.RLock()
	defer s.statusCacheMu.RUnlock()
	return s.statusCache[deviceID]
}

// initStatusCache loads all device statuses from the DB into statusCache and
// lastSynced at startup. This ensures a process restart starts from the DB's
// current state (not blank), so devices don't momentarily appear "unknown".
func (s *HeartbeatService) initStatusCache(ctx context.Context) {
	rows, err := s.mainDB.QueryContext(ctx, "SELECT id, status FROM devices")
	if err != nil {
		slog.Error("initStatusCache query failed", "error", err)
		return
	}
	defer rows.Close()
	s.statusCacheMu.Lock()
	n := 0
	for rows.Next() {
		var id int64
		var status string
		if err := rows.Scan(&id, &status); err != nil {
			continue
		}
		s.statusCache[id] = status
		s.lastSynced[id] = status // DB and cache start in sync
		n++
	}
	s.statusCacheMu.Unlock()
	slog.Info("statusCache initialized from DB", "devices", n)
}

// syncStatusLoop is the SOLE writer of devices.status to the main DB. It runs
// every 30s, diffing the in-memory statusCache against lastSynced and writing
// only the changes. In steady state (no status changes), this is zero writes.
// Probes never touch devices.status — they only update statusCache — so there's
// no concurrent-write race on the main DB.
func (s *HeartbeatService) syncStatusLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.syncStatus(ctx)
		}
	}
}

// syncStatus writes changed device statuses from the in-memory cache to the DB.
func (s *HeartbeatService) syncStatus(ctx context.Context) {
	// Snapshot the cache under a short read lock.
	s.statusCacheMu.RLock()
	changed := make([]struct {
		id     int64
		status string
	}, 0)
	for id, status := range s.statusCache {
		if s.lastSynced[id] != status {
			changed = append(changed, struct {
				id     int64
				status string
			}{id, status})
		}
	}
	s.statusCacheMu.RUnlock()

	if len(changed) == 0 {
		return // steady state, zero DB writes
	}

	// Write all changes in a single transaction (one commit, no concurrency).
	tx, err := s.mainDB.BeginTx(ctx, nil)
	if err != nil {
		slog.Error("syncStatus begin tx failed", "error", err)
		return
	}
	for _, c := range changed {
		if _, err := tx.ExecContext(ctx, "UPDATE devices SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", c.status, c.id); err != nil {
			slog.Error("syncStatus update failed", "device_id", c.id, "error", err)
		}
	}
	if err := tx.Commit(); err != nil {
		slog.Error("syncStatus commit failed", "error", err)
		return
	}

	// Update lastSynced under a short write lock.
	s.statusCacheMu.Lock()
	for _, c := range changed {
		s.lastSynced[c.id] = c.status
	}
	s.statusCacheMu.Unlock()

	slog.Info("synced device statuses to DB", "changed", len(changed))
}

// safeEvaluateDeviceStatus was removed: the alert engine has been deleted (the
// product does not build alerting — see AGENTS.md product vision). Device
// status changes are still recorded in the status cache and synced to the DB
// by syncStatusLoop; they just no longer fire alert-rule evaluation.
// (cleanupOldResults was also removed: heartbeat_results pruning is now handled
// by the unified retention sweeper in cleanup.Service, so there's a single
// source of truth for the retention window across all detail tables.)
// (setDeviceStatus was inlined into applyDeviceVerdict so the entire
// read-modify-write of device status is under one mutex — the previous split
// had GetDevice/setDeviceStatus outside the lock, racing under concurrency.)

func (s *HeartbeatService) isDue(_ context.Context, cfg db.HeartbeatConfig) bool {
	interval := time.Duration(cfg.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}

	// Read the last probe time from the in-memory map — NOT from the heartbeat
	// store. The store's writes are batched/async, so querying it for the last
	// checked_at can lag and cause isDue to fire out of cadence.
	s.lastProbeMu.RLock()
	last := s.lastProbe[cfg.ID]
	s.lastProbeMu.RUnlock()

	if last.IsZero() {
		return true // never probed yet
	}
	return time.Since(last) >= interval
}

// GetHistory returns paginated heartbeat results for a device within a time range.
func (s *HeartbeatService) GetHistory(ctx context.Context, deviceID int64, from, to time.Time, limit, offset int32) (*domain.HeartbeatHistoryListResponse, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}

	// Read history from the dedicated heartbeat store (separate DB).
	hq := s.store.Queries()
	results, err := hq.ListHeartbeatResultsByTimeRange(ctx, db.ListHeartbeatResultsByTimeRangeParams{
		DeviceID:    deviceID,
		CheckedAt:   from,
		CheckedAt_2: to,
		Limit:       int64(limit),
		Offset:      int64(offset),
	})
	if err != nil {
		return nil, err
	}

	total, err := hq.CountHeartbeatResultsByTimeRange(ctx, db.CountHeartbeatResultsByTimeRangeParams{
		DeviceID:    deviceID,
		CheckedAt:   from,
		CheckedAt_2: to,
	})
	if err != nil {
		return nil, err
	}

	responses := make([]domain.HeartbeatResultResponse, len(results))
	for i, r := range results {
		responses[i] = toHeartbeatResultResponse(r)
	}

	return &domain.HeartbeatHistoryListResponse{
		Results: responses,
		Total:   int(total),
	}, nil
}

// GetStats returns aggregated heartbeat statistics for a device within a time range.
func (s *HeartbeatService) GetStats(ctx context.Context, deviceID int64, from, to time.Time) (*domain.HeartbeatStatsResponse, error) {
	// Read stats from the dedicated heartbeat store (separate DB).
	stats, err := s.store.Queries().GetHeartbeatStats(ctx, db.GetHeartbeatStatsParams{
		DeviceID:    deviceID,
		CheckedAt:   from,
		CheckedAt_2: to,
	})
	if err != nil {
		return nil, err
	}

	return &domain.HeartbeatStatsResponse{
		AvgLatencyMs: stats.AvgLatencyMs,
		SuccessCount: stats.SuccessCount,
		FailCount:    stats.FailCount,
		TimeoutCount: stats.TimeoutCount,
	}, nil
}

// ListResults returns the most recent heartbeat results for a device, optionally
// filtered by a [from, to] time range, paginated. It reads from the dedicated
// heartbeat store (separate DB), NOT the main DB — the main DB's
// heartbeat_results table is a stale leftover from before the store migration
// and is no longer written to, so reading it would surface frozen/old timestamps.
func (s *HeartbeatService) ListResults(ctx context.Context, deviceID int64, from, to time.Time, limit, offset int32) ([]db.HeartbeatResult, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}

	// When no time filter is supplied (zero values), we want "latest N results
	// regardless of time". ListHeartbeatResultsByTimeRange uses checked_at >= ?
	// AND checked_at <= ?, which a zero time would wrongly restrict to epoch.
	// Open the range to ±68 years so an unset filter matches everything.
	if from.IsZero() {
		from = time.Unix(0, 0)
	}
	if to.IsZero() {
		to = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	results, err := s.store.Queries().ListHeartbeatResultsByTimeRange(ctx, db.ListHeartbeatResultsByTimeRangeParams{
		DeviceID:    deviceID,
		CheckedAt:   from,
		CheckedAt_2: to,
		Limit:       int64(limit),
		Offset:      int64(offset),
	})
	if err != nil {
		return nil, err
	}
	if results == nil {
		results = []db.HeartbeatResult{}
	}
	return results, nil
}

// toHeartbeatResultResponse converts a db.HeartbeatResult to a domain.HeartbeatResultResponse.
func toHeartbeatResultResponse(r db.HeartbeatResult) domain.HeartbeatResultResponse {
	return domain.HeartbeatResultResponse{
		ID:           r.ID,
		DeviceID:     r.DeviceID,
		ConfigID:     r.ConfigID,
		Status:       r.Status,
		LatencyMs:    r.LatencyMs,
		ErrorMessage: r.ErrorMessage,
		CheckedAt:    r.CheckedAt,
	}
}
