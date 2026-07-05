// Package runner connects the v2 detection Engine to the scan-task/run/result
// persistence layer. It is the replacement for the v1 scanFunc closure: given a
// task config, it runs the engine, records the run + per-host results, and
// applies the device bridge (create/update devices + heartbeat configs).
//
// Unlike v1, the runner depends only on:
//   - the v2 Engine (detection)
//   - *db.Queries (sqlc-generated persistence, reused as-is)
//   - the heartbeat HeartbeatCreator interface (for new-device config seeding)
//
// It deliberately reuses the existing scan_tasks / scan_task_runs / scan_results
// tables so the result-browsing API surface is unchanged.
package runner

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/engine"
)

// HeartbeatCreator creates heartbeat configs for newly-discovered devices.
// Implemented by *service.HeartbeatService; defined here to break the import
// cycle (runner can't import service, which imports scannerv2).
type HeartbeatCreator interface {
	CreateConfigs(ctx context.Context, deviceID int64, configs []scannerv2.HeartbeatSpec) error
}

// Runner executes scan tasks via the v2 engine and persists outcomes.
type Runner struct {
	engine    *engine.Engine   // nil-safe: when nil, Runner is a no-op (used if engine init failed)
	queries   *db.Queries      // sqlc queries for run/result/task rows
	dbConn    *sql.DB          // raw connection for the device-bridge upserts (sqlc has no per-IP device lookup)
	heartbeat HeartbeatCreator // may be nil (heartbeat config creation skipped)
	logger    *slog.Logger
}

// New constructs a Runner. engine may be nil (the runner will log and no-op on
// each Run), letting the scheduler stay alive even if the engine failed to init.
func New(engine *engine.Engine, queries *db.Queries, dbConn *sql.DB, heartbeat HeartbeatCreator, logger *slog.Logger) *Runner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{engine: engine, queries: queries, dbConn: dbConn, heartbeat: heartbeat, logger: logger}
}

// PersistManualDevice runs a single HostReport (synthesized for a manually-
// added device) through the device bridge, creating/updating the devices row
// and seeding heartbeat configs for new devices. Used by the AddDevices API.
// Returns (isNew, error).
func (rn *Runner) PersistManualDevice(ctx context.Context, rep scannerv2.HostReport) (bool, error) {
	isNew, _ := rn.applyDeviceBridge(ctx, rep)
	return isNew, nil
}

// Run executes one scan task: creates a run record, runs the engine over
// targets, persists per-host results, applies the device bridge, and finalizes
// the run + task status. It never returns an error that would crash the
// scheduler — failures are recorded on the run row and logged.
//
// timeout is the per-host pipeline timeout; concurrentHosts caps parallelism.
func (rn *Runner) Run(ctx context.Context, taskID int64, targets string, timeout time.Duration, concurrentHosts int, persistRawEvidence bool) {
	if rn.engine == nil {
		// Engine failed to init at startup. Record a failed run so the operator
		// can see (via the UI / runs API) that the task fired but couldn't run,
		// rather than the trigger appearing to succeed silently.
		rn.logger.Error("scan runner: engine not initialized, marking run failed", "task_id", taskID)
		start := time.Now()
		run, err := rn.queries.CreateScanTaskRun(ctx, db.CreateScanTaskRunParams{
			TaskID:    taskID,
			StartedAt: &start,
		})
		if err != nil {
			rn.logger.Error("scan runner: create run (nil-engine) failed", "task_id", taskID, "error", err)
			return
		}
		rn.failRun(ctx, run.ID, taskID, 0, "scan engine not initialized")
		return
	}
	start := time.Now()

	// 1. Create the run row (status=running).
	run, err := rn.queries.CreateScanTaskRun(ctx, db.CreateScanTaskRunParams{
		TaskID:    taskID,
		StartedAt: &start,
	})
	if err != nil {
		rn.logger.Error("scan runner: create run failed", "task_id", taskID, "error", err)
		return
	}
	runID := run.ID

	// 2. Execute the engine. The engine's per-host timeout + concurrency are
	//    applied via a transient reconfiguration; we just pass targets through.
	rn.engine.Orchestrator.SetTimeouts(timeout, concurrentHosts)
	reports, err := rn.engine.ScanTargets(ctx, targets, false)
	duration := time.Since(start)

	if err != nil {
		rn.failRun(ctx, runID, taskID, duration, fmt.Sprintf("scan failed: %v", err))
		return
	}

	// 3. Persist per-host results + apply the device bridge, tallying stats.
	totalHosts := len(reports)
	aliveHosts := 0
	newHosts := 0
	updatedHosts := 0
	for _, rep := range reports {
		if !rep.Alive {
			continue
		}
		aliveHosts++
		isNew, upd := rn.persistHost(ctx, taskID, runID, rep, persistRawEvidence)
		if isNew {
			newHosts++
		}
		if upd {
			updatedHosts++
		}
	}

	// 4. Finalize the run.
	finish := time.Now()
	if err := rn.queries.UpdateScanTaskRun(ctx, db.UpdateScanTaskRunParams{
		Status:       "completed",
		TotalHosts:   int64(totalHosts),
		AliveHosts:   int64(aliveHosts),
		NewHosts:     int64(newHosts),
		UpdatedHosts: int64(updatedHosts),
		DurationMs:   duration.Milliseconds(),
		ErrorMessage: "",
		FinishedAt:   &finish,
		ID:           runID,
	}); err != nil {
		rn.logger.Error("scan runner: finalize run failed", "run_id", runID, "error", err)
	}
	// 5. Update task last-run status (best-effort).
	_ = rn.queries.UpdateScanTaskStatus(ctx, db.UpdateScanTaskStatusParams{
		LastRunAt:     &finish,
		LastRunStatus: strPtr("completed"),
		ID:            taskID,
	})
}

// failRun marks a run failed and updates the task's last-run status.
func (rn *Runner) failRun(ctx context.Context, runID, taskID int64, duration time.Duration, msg string) {
	rn.logger.Error("scan runner: run failed", "run_id", runID, "task_id", taskID, "error", msg)
	finish := time.Now()
	_ = rn.queries.UpdateScanTaskRun(ctx, db.UpdateScanTaskRunParams{
		Status:       "failed",
		DurationMs:   duration.Milliseconds(),
		ErrorMessage: msg,
		FinishedAt:   &finish,
		ID:           runID,
	})
	_ = rn.queries.UpdateScanTaskStatus(ctx, db.UpdateScanTaskStatusParams{
		LastRunAt:     &finish,
		LastRunStatus: strPtr("failed"),
		ID:            taskID,
	})
}

// persistHost writes the per-host scan_result, then upserts the device and (for
// new devices) seeds heartbeat configs. Returns (isNew, wasUpdated).
func (rn *Runner) persistHost(ctx context.Context, taskID, runID int64, rep scannerv2.HostReport, _ bool) (bool, bool) {
	// Write the scan_results row.
	ports, services, snmpData := reportJSONFields(rep)
	promURL, neURL, neData := reportPromFields(rep)
	if _, err := rn.queries.CreateScanResult(ctx, db.CreateScanResultParams{
		TaskID:               taskID,
		RunID:                &runID,
		Ip:                   rep.IP,
		Alive:                boolToInt(rep.Alive),
		RttMs:                rep.RTTMs,
		Ports:                ports,
		Services:             services,
		SnmpData:             snmpData,
		PrometheusDetected:   boolToInt(promURL != ""),
		PrometheusUrl:        promURL,
		NodeExporterDetected: boolToInt(neURL != ""),
		NodeExporterUrl:      neURL,
		NodeExporterData:     neData,
	}); err != nil {
		rn.logger.Warn("scan runner: insert scan_result failed", "ip", rep.IP, "error", err)
	}

	// Device bridge.
	return rn.applyDeviceBridge(ctx, rep)
}

// reportJSONFields serializes a HostReport's ports/services/snmp into the JSON
// strings the scan_results table expects.
func reportJSONFields(rep scannerv2.HostReport) (string, string, string) {
	ports := "[]"
	if len(rep.Evidence) > 0 {
		portList := uniqueOpenPorts(rep.Evidence)
		if b, err := json.Marshal(portList); err == nil {
			ports = string(b)
		}
	}
	services := "{}"
	if len(rep.Services) > 0 {
		m := make(map[string]any, len(rep.Services))
		for _, s := range rep.Services {
			m[fmt.Sprintf("%s/%d", s.Service, s.Port)] = map[string]any{
				"confidence": s.Confidence,
				"metadata":   s.Metadata,
			}
		}
		if b, err := json.Marshal(m); err == nil {
			services = string(b)
		}
	}
	snmp := "{}"
	for _, e := range rep.Evidence {
		if e.Kind == "snmp" && e.RawData != nil {
			if b, err := json.Marshal(e.RawData); err == nil {
				snmp = string(b)
			}
			break
		}
	}
	return ports, services, snmp
}

// reportPromFields extracts prometheus/node_exporter URLs + NE data from the
// report's collected data / device fields.
func reportPromFields(rep scannerv2.HostReport) (promURL, neURL, neData string) {
	if rep.Device.Fields != nil {
		promURL = rep.Device.Fields["prometheus_url"]
		neURL = rep.Device.Fields["node_exporter_url"]
	}
	if neURL != "" && rep.Device.Fields != nil {
		// Minimal NE data record for the column.
		m := map[string]string{
			"metrics_url": neURL,
		}
		for _, k := range []string{"kernel_version", "os_type", "memory_total_bytes", "cpu_count"} {
			if v := rep.Device.Fields[k]; v != "" {
				m[k] = v
			}
		}
		if b, err := json.Marshal(m); err == nil {
			neData = string(b)
		}
	}
	return
}

// uniqueOpenPorts returns the sorted, deduped list of open ports from evidence.
func uniqueOpenPorts(evs []scannerv2.Evidence) []int {
	seen := map[int]bool{}
	var out []int
	for _, e := range evs {
		if e.Kind == "port_open" && e.Port > 0 && !seen[e.Port] {
			seen[e.Port] = true
			out = append(out, e.Port)
		}
	}
	// simple insertion sort (small N)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func strPtr(s string) *string { return &s }
