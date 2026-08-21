// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

// Package metrics holds the process-global Prometheus collectors for MiBee's
// own operational signals (device counts, heartbeat outcomes, scanner runs).
// It lives OUTSIDE internal/api/handler so the service layer (heartbeat,
// scanner runner, scheduler) can increment counters without importing the
// HTTP layer — handler imports service, never the reverse (#238).
//
// Everything registers on the DefaultRegisterer in init() (process-global,
// like /metrics itself). Consumers must .Inc()/.Observe()/.Set(); nothing here
// needs a handle.
package metrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"mibee-steward/internal/db"
)

var (
	// MibeeDevicesTotal tracks the total number of devices by status and type.
	// Refreshed by handler.UpdateDeviceMetrics (seeded at router start and
	// after device mutations).
	MibeeDevicesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mibee_devices_total",
			Help: "Total number of devices",
		},
		[]string{"status", "type"},
	)

	// MibeeAgentLastReportTimestamp is the Unix time of an agent's last
	// accepted report, keyed by agent_id. Set by the agent-report handler on
	// every (authenticated) report, including empty and anti-entropy fast-path
	// ones — the "is this agent alive" signal for the AgentReportStale alert
	// (#279).
	MibeeAgentLastReportTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mibee_agent_last_report_timestamp_seconds",
			Help: "Unix timestamp of the last accepted agent report",
		},
		[]string{"agent_id"},
	)

	// MibeeDBSizeBytes tracks the on-disk size of the SQLite files (main +
	// heartbeat store), split into the DB file itself and its WAL sidecar.
	// Refreshed by the cleanup service's maintenance pass each sweep (#280) —
	// the growth baseline for capacity planning and the db-growth alert.
	MibeeDBSizeBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mibee_db_size_bytes",
			Help: "SQLite database file sizes (db = main|heartbeat, kind = db|wal)",
		},
		[]string{"db", "kind"},
	)

	// MibeeDBTableRows tracks row counts of the high-volume tables so retention
	// effectiveness and growth trends are observable. Refreshed with the
	// maintenance pass (#280).
	MibeeDBTableRows = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mibee_db_table_rows",
			Help: "Row counts of high-volume tables (retention effectiveness / growth)",
		},
		[]string{"db", "table"},
	)

	// MibeeHeartbeatChecksTotal counts heartbeat probe outcomes. Incremented
	// by HeartbeatService.probeAndRecord per probe (#238 — previously
	// registered but never written, leaving the HeartbeatFailures alert dead).
	MibeeHeartbeatChecksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mibee_heartbeat_checks_total",
			Help: "Total heartbeat checks",
		},
		[]string{"status"},
	)

	// MibeeHeartbeatLatencySeconds records heartbeat probe latency by method.
	MibeeHeartbeatLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mibee_heartbeat_latency_seconds",
			Help:    "Heartbeat check latency",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method"},
	)

	// MibeeScannerRunsTotal counts scan runs by outcome. Incremented by the
	// runner's complete/fail paths (#238).
	MibeeScannerRunsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mibee_scanner_runs_total",
			Help: "Total number of scan runs by status",
		},
		[]string{"status"},
	)

	// MibeeScannerDurationSeconds records scan execution duration.
	MibeeScannerDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "mibee_scanner_duration_seconds",
			Help:    "Duration of scan executions",
			Buckets: prometheus.DefBuckets,
		},
	)

	// MibeeScannerHostsDiscovered counts total alive hosts found by scans.
	MibeeScannerHostsDiscovered = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "mibee_scanner_hosts_discovered",
			Help: "Total number of hosts discovered",
		},
	)

	// MibeeScannerTasksTotal gauges the scan-task count by enabled state.
	// Refreshed by RefreshScannerTaskGauges at scheduler start and after task
	// CRUD (#238).
	MibeeScannerTasksTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mibee_scanner_tasks_total",
			Help: "Total number of scan tasks by status",
		},
		[]string{"status"},
	)
)

func init() {
	prometheus.MustRegister(MibeeDevicesTotal)
	prometheus.MustRegister(MibeeHeartbeatChecksTotal)
	prometheus.MustRegister(MibeeHeartbeatLatencySeconds)
	prometheus.MustRegister(MibeeScannerRunsTotal)
	prometheus.MustRegister(MibeeScannerDurationSeconds)
	prometheus.MustRegister(MibeeScannerHostsDiscovered)
	prometheus.MustRegister(MibeeScannerTasksTotal)
	prometheus.MustRegister(MibeeAgentLastReportTimestamp)
	prometheus.MustRegister(MibeeDBSizeBytes)
	prometheus.MustRegister(MibeeDBTableRows)
}

// RefreshScannerTaskGauges recomputes mibee_scanner_tasks_total{status} from
// the DB. Best-effort: errors are returned to the caller, who logs and moves
// on — a stale gauge never fails a scan-task write.
func RefreshScannerTaskGauges(ctx context.Context, queries *db.Queries) error {
	tasks, err := queries.ListScanTasks(ctx, db.ListScanTasksParams{Limit: 100000, Offset: 0})
	if err != nil {
		return err
	}
	enabled, disabled := 0, 0
	for _, t := range tasks {
		if t.Enabled == 1 {
			enabled++
		} else {
			disabled++
		}
	}
	MibeeScannerTasksTotal.WithLabelValues("enabled").Set(float64(enabled))
	MibeeScannerTasksTotal.WithLabelValues("disabled").Set(float64(disabled))
	return nil
}
