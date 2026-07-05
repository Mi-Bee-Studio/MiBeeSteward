package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/alert"
	"mibee-steward/internal/service/probe"
	"mibee-steward/internal/service/scannerv2"
)

// HeartbeatService manages heartbeat scheduling and result processing.
type HeartbeatService struct {
	queries      *db.Queries
	cfg          config.HeartbeatConfig
	cancel       context.CancelFunc
	failCounts   map[int64]int // deviceID -> consecutive failure count
	failCountsMu sync.Mutex
	alertEngine  *alert.Engine
}

// NewHeartbeatService creates a new HeartbeatService.
func NewHeartbeatService(dbConn db.DBTX, cfg *config.Config) *HeartbeatService {
	return &HeartbeatService{
		queries:    db.New(dbConn),
		cfg:        cfg.Heartbeat,
		failCounts: make(map[int64]int),
	}
}

// Start begins the heartbeat scheduler loop in the background.
func (s *HeartbeatService) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)
	defer s.cancel()

	// Cleanup old results on start
	s.cleanupOldResults(ctx)

	ticker := time.NewTicker(10 * time.Second)
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

// Stop cancels the scheduler context.
func (s *HeartbeatService) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// GetQueries returns the underlying sqlc queries for handler use.
func (s *HeartbeatService) GetQueries() *db.Queries {
	return s.queries
}

// SetAlertEngine sets the alert engine for evaluating device status changes.
func (s *HeartbeatService) SetAlertEngine(eng *alert.Engine) {
	s.alertEngine = eng
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

func (s *HeartbeatService) runChecks(ctx context.Context) {
	configs, err := s.queries.ListEnabledConfigs(ctx)
	if err != nil {
		slog.Error("heartbeat error listing configs", "error", err)
		return
	}

	for _, cfg := range configs {
		// Check if this config is due for a check based on its interval
		if !s.isDue(ctx, cfg) {
			continue
		}

		s.checkOne(ctx, cfg)
	}
}
func (s *HeartbeatService) checkOne(ctx context.Context, cfg db.HeartbeatConfig) {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	prober := GetProber(cfg.Method, cfg.SnmpCommunity, cfg.SnmpOid)
	prober = probe.NewRetryProber(prober, 3, 1*time.Second)
	result, err := prober.Probe(ctx, cfg.Target, timeout)
	if err != nil {
		slog.Error("heartbeat probe error", "config_id", cfg.ID, "error", err)
		return
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

	// Write result
	_, err = s.queries.CreateResult(ctx, db.CreateResultParams{
		DeviceID:     cfg.DeviceID,
		ConfigID:     cfg.ID,
		Status:       status,
		LatencyMs:    latencyMs,
		ErrorMessage: errorMsg,
		CheckedAt:    time.Now(),
	})
	if err != nil {
		slog.Error("heartbeat error writing result", "config_id", cfg.ID, "error", err)
		return
	}

	// Update device status
	s.updateDeviceStatus(ctx, cfg.DeviceID, result.Success)
}

func (s *HeartbeatService) updateDeviceStatus(ctx context.Context, deviceID int64, success bool) {
	s.failCountsMu.Lock()
	defer s.failCountsMu.Unlock()

	if success {
		if s.failCounts[deviceID] > 0 {
			s.failCounts[deviceID] = 0
		}
		// Set online if currently offline
		device, err := s.queries.GetDevice(ctx, deviceID)
		if err != nil || device.Status == "online" {
			return
		}
		oldStatus := device.Status
		s.setDeviceStatus(ctx, deviceID, device, "online")
		// Notify alert engine of status change
		if s.alertEngine != nil {
			go s.safeEvaluateDeviceStatus(ctx, deviceID, oldStatus, "online")
		}
		return
	}

	// Failure path: increment counter
	s.failCounts[deviceID]++
	count := s.failCounts[deviceID]

	if count < 3 {
		slog.Info("heartbeat failure, not yet at threshold", "device_id", deviceID, "fail_count", count, "threshold", 3)
		return
	}

	// At or past threshold — mark offline
	device, err := s.queries.GetDevice(ctx, deviceID)
	if err != nil || device.Status == "offline" {
		return
	}
	oldStatus := device.Status
	s.setDeviceStatus(ctx, deviceID, device, "offline")
	// Notify alert engine of status change
	if s.alertEngine != nil {
		go s.safeEvaluateDeviceStatus(ctx, deviceID, oldStatus, "offline")
	}
}

// safeEvaluateDeviceStatus wraps alertEngine.EvaluateDeviceStatus with panic
// recovery. These run as fire-and-forget goroutines from the heartbeat tick;
// a panic inside the alert engine would otherwise crash the whole process.
func (s *HeartbeatService) safeEvaluateDeviceStatus(ctx context.Context, deviceID int64, oldStatus, newStatus string) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("alert engine panic recovered", "device_id", deviceID, "panic", r)
		}
	}()
	if err := s.alertEngine.EvaluateDeviceStatus(ctx, deviceID, oldStatus, newStatus); err != nil {
		slog.Error("alert engine failed to evaluate device status", "device_id", deviceID, "error", err)
	}
}

func (s *HeartbeatService) setDeviceStatus(ctx context.Context, deviceID int64, device db.Device, newStatus string) {
	// Update ONLY the status column. The previous full-row UpdateDevice call
	// rewrote every column from a snapshot read earlier in the tick, racing with
	// concurrent edits (a user renaming a device in the UI between the GetDevice
	// read and this write would have their edit silently reverted).
	err := s.queries.UpdateDeviceStatus(ctx, db.UpdateDeviceStatusParams{
		Status: newStatus,
		ID:     device.ID,
	})
	if err != nil {
		slog.Error("heartbeat error updating device status", "device_id", deviceID, "error", err)
	} else {
		slog.Info("device status changed", "device_id", deviceID, "status", newStatus)
	}
}

func (s *HeartbeatService) cleanupOldResults(ctx context.Context) {
	retentionDays := s.cfg.RetentionDays
	if retentionDays <= 0 {
		retentionDays = 30
	}
	cutoff := time.Now().AddDate(0, 0, -int(retentionDays))

	affected, err := s.queries.DeleteOlderThan(ctx, cutoff)
	if err != nil {
		slog.Error("heartbeat error cleaning old results", "error", err)
		return
	}
	if affected > 0 {
		slog.Info("cleaned up old heartbeat results", "count", affected)
	}
}

func (s *HeartbeatService) isDue(ctx context.Context, cfg db.HeartbeatConfig) bool {
	interval := time.Duration(cfg.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}

	lastCheckedAt, err := s.queries.GetLatestCheckedAt(ctx, cfg.ID)
	if err != nil {
		// No results yet, due immediately
		return true
	}

	return time.Since(lastCheckedAt) >= interval
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

	results, err := s.queries.ListHeartbeatResultsByTimeRange(ctx, db.ListHeartbeatResultsByTimeRangeParams{
		DeviceID:    deviceID,
		CheckedAt:   from,
		CheckedAt_2: to,
		Limit:       int64(limit),
		Offset:      int64(offset),
	})
	if err != nil {
		return nil, err
	}

	total, err := s.queries.CountHeartbeatResultsByTimeRange(ctx, db.CountHeartbeatResultsByTimeRangeParams{
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
	stats, err := s.queries.GetHeartbeatStats(ctx, db.GetHeartbeatStatsParams{
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
