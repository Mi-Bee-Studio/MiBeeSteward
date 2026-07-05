package handler

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"mibee-steward/internal/db"
)

var (
	// MibeeDevicesTotal tracks the total number of devices by status and type.
	MibeeDevicesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mibee_devices_total",
			Help: "Total number of devices",
		},
		[]string{"status", "type"},
	)

	// MibeeHeartbeatChecksTotal counts heartbeat checks by status.
	MibeeHeartbeatChecksTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mibee_heartbeat_checks_total",
			Help: "Total heartbeat checks",
		},
		[]string{"status"},
	)

	// MibeeHeartbeatLatencySeconds records heartbeat check latency.
	MibeeHeartbeatLatencySeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mibee_heartbeat_latency_seconds",
			Help:    "Heartbeat check latency",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method"},
	)

	// MibeeScannerTasksTotal tracks the total number of scan tasks by status.
	MibeeScannerTasksTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "mibee_scanner_tasks_total",
			Help: "Total number of scan tasks by status",
		},
		[]string{"status"},
	)

	// MibeeScannerRunsTotal counts scan runs by status.
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

	// MibeeScannerHostsDiscovered counts total hosts discovered by scanner.
	MibeeScannerHostsDiscovered = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "mibee_scanner_hosts_discovered",
			Help: "Total number of hosts discovered by scanner",
		},
	)
)

func init() {
	prometheus.MustRegister(MibeeDevicesTotal)
	prometheus.MustRegister(MibeeHeartbeatChecksTotal)
	prometheus.MustRegister(MibeeHeartbeatLatencySeconds)
	prometheus.MustRegister(MibeeScannerTasksTotal)
	prometheus.MustRegister(MibeeScannerRunsTotal)
	prometheus.MustRegister(MibeeScannerDurationSeconds)
	prometheus.MustRegister(MibeeScannerHostsDiscovered)
}

// MetricsHandler returns an http.Handler that serves Prometheus metrics.
func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

// UpdateDeviceMetrics queries the database and updates the MibeeDevicesTotal gauge.
func UpdateDeviceMetrics(ctx context.Context, dbtx db.DBTX) {
	q := db.New(dbtx)

	statuses, err := q.CountByStatus(ctx)
	if err != nil {
		return
	}

	// Reset all device gauges before setting new values to handle
	// label combinations that no longer exist.
	MibeeDevicesTotal.Reset()

	for _, s := range statuses {
		MibeeDevicesTotal.WithLabelValues(s.Status, "").Set(float64(s.Count))
	}
}
