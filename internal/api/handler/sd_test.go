package handler_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"mibee-steward/internal/api/handler"
	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"

	_ "modernc.org/sqlite"
)

func setupSDDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// TestMergeLabels verifies the 3-layer label merge priority.
func TestMergeLabels(t *testing.T) {
	tests := []struct {
		name      string
		static    map[string]string
		dynamic   map[string]string
		perDevice map[string]string
		expected  map[string]string
	}{
		{
			name:      "all empty",
			static:    map[string]string{},
			dynamic:   map[string]string{},
			perDevice: map[string]string{},
			expected:  map[string]string{},
		},
		{
			name: "static only",
			static: map[string]string{
				"env":     "production",
				"team":    "infra",
				"region":  "us-east",
			},
			dynamic:   map[string]string{},
			perDevice: map[string]string{},
			expected: map[string]string{
				"env":    "production",
				"team":   "infra",
				"region": "us-east",
			},
		},
		{
			name: "dynamic overrides static",
			static: map[string]string{
				"env":   "production",
				"team":  "infra",
			},
			dynamic: map[string]string{
				"team":          "networking",
				"scan_task_name": "daily-scan",
			},
			perDevice: map[string]string{},
			expected: map[string]string{
				"env":            "production",
				"team":           "networking",
				"scan_task_name": "daily-scan",
			},
		},
		{
			name: "per-device overrides dynamic and static",
			static: map[string]string{
				"env":    "production",
				"team":   "infra",
				"region": "us-east",
			},
			dynamic: map[string]string{
				"team":           "networking",
				"device_type":    "server",
				"scan_task_name": "daily-scan",
			},
			perDevice: map[string]string{
				"team":        "storage",
				"custom_label": "special",
			},
			expected: map[string]string{
				"env":            "production",
				"region":         "us-east",
				"team":           "storage",
				"device_type":    "server",
				"scan_task_name": "daily-scan",
				"custom_label":   "special",
			},
		},
		{
			name: "nil maps treated as empty",
			static: map[string]string{
				"env": "staging",
			},
			dynamic:   nil,
			perDevice: nil,
			expected: map[string]string{
				"env": "staging",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.MergeLabels(tt.static, tt.dynamic, tt.perDevice)
			require.Equal(t, tt.expected, result)
		})
	}
}

// TestBuildScannerTargets tests scanner target generation with mock data.
func TestBuildScannerTargets(t *testing.T) {
	d := setupSDDB(t)
	queries := db.New(d)
	ctx := context.Background()

	// Create a scan task with global labels.
	taskLabels, _ := json.Marshal(map[string]string{
		"env":   "production",
		"team":  "infra",
		"cloud": "aws",
	})
	_, err := d.Exec(
		`INSERT INTO scan_tasks (name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
		"daily-scan", "192.168.1.0/24", "0 3 * * *", "{}", string(taskLabels), 30, 10,
	)
	require.NoError(t, err)

	var taskID int64
	err = d.QueryRow("SELECT last_insert_rowid()").Scan(&taskID)
	require.NoError(t, err)

	// Create a device with per-device prometheus_labels.
	devLabels, _ := json.Marshal(map[string]string{
		"team":     "storage",
		"tier":     "gold",
	})
	_, err = d.Exec(
		`INSERT INTO devices (name, type, ip_address, status, prometheus_labels)
		VALUES (?, ?, ?, ?, ?)`,
		"storage-01", "nas", "10.0.0.50", "online", string(devLabels),
	)
	require.NoError(t, err)

	// Insert a scan result with prometheus_detected=1 for the registered device.
	servicesJSON, _ := json.Marshal([]map[string]string{
		{"service": "ssh"},
		{"service": "http"},
		{"service": "prometheus"},
	})
	_, err = d.Exec(
		`INSERT INTO scan_results (task_id, ip, alive, prometheus_detected, prometheus_url, node_exporter_detected, services)
		VALUES (?, ?, 1, 1, ?, 1, ?)`,
		taskID, "10.0.0.50", "10.0.0.50:9090", string(servicesJSON),
	)
	require.NoError(t, err)

	// Insert another scan result with prometheus_detected=0 (should be excluded).
	_, err = d.Exec(
		`INSERT INTO scan_results (task_id, ip, alive, prometheus_detected, services)
		VALUES (?, ?, 1, 0, '[]')`,
		taskID, "10.0.0.51",
	)
	require.NoError(t, err)

	// Insert an unregistered device with prometheus_detected=1.
	_, err = d.Exec(
		`INSERT INTO scan_results (task_id, ip, alive, prometheus_detected, prometheus_url, node_exporter_detected, services)
		VALUES (?, ?, 1, 1, ?, 0, '[]')`,
		taskID, "10.0.0.99", "10.0.0.99:9090",
	)
	require.NoError(t, err)

	targets := handler.BuildScannerTargets(ctx, queries)
	require.Len(t, targets, 2, "should have exactly 2 scanner targets")

	// Find the registered device target.
	var found50 bool
	for _, tgt := range targets {
		if len(tgt.Targets) > 0 && tgt.Targets[0] == "10.0.0.50:9090" {
			found50 = true
			// Per-device "team" should override static "team".
			require.Equal(t, "storage", tgt.Labels["team"])
			// Per-device "tier" should be present.
			require.Equal(t, "gold", tgt.Labels["tier"])
			// Static "env" and "cloud" should survive.
			require.Equal(t, "production", tgt.Labels["env"])
			require.Equal(t, "aws", tgt.Labels["cloud"])
			// Dynamic labels.
			require.Equal(t, "daily-scan", tgt.Labels["scan_task_name"])
			require.Equal(t, "scanner", tgt.Labels["__source"])
			require.Equal(t, "true", tgt.Labels["has_node_exporter"])
			require.Equal(t, "ssh,http,prometheus", tgt.Labels["discovered_services"])
			// Device type from device record.
			require.Equal(t, "nas", tgt.Labels["device_type"])
			require.Equal(t, "storage-01", tgt.Labels["device_name"])
		}
	}
	require.True(t, found50, "should find registered device 10.0.0.50")

	// Find the unregistered device target.
	var found99 bool
	for _, tgt := range targets {
		if len(tgt.Targets) > 0 && tgt.Targets[0] == "10.0.0.99:9090" {
			found99 = true
			// No per-device overrides — should use static + dynamic.
			require.Equal(t, "infra", tgt.Labels["team"], "unregistered device should use static team")
			require.Equal(t, "production", tgt.Labels["env"])
			require.Equal(t, "daily-scan", tgt.Labels["scan_task_name"])
			require.Equal(t, "scanner", tgt.Labels["__source"])
			// node_exporter_detected=0, so no has_node_exporter.
			_, ok := tgt.Labels["has_node_exporter"]
			require.False(t, ok, "should not have has_node_exporter when not detected")
		}
	}
	require.True(t, found99, "should find unregistered device 10.0.0.99")
}

// TestBuildScannerTargets_EmptyDB verifies no scanner targets when DB is empty.
func TestBuildScannerTargets_EmptyDB(t *testing.T) {
	d := setupSDDB(t)
	queries := db.New(d)
	ctx := context.Background()

	targets := handler.BuildScannerTargets(ctx, queries)
	require.Empty(t, targets)
}

// TestSDIncludesScannerTargets is an integration test that verifies the /sd
// response includes scanner-discovered devices alongside heartbeat targets.
func TestSDIncludesScannerTargets(t *testing.T) {
	d := setupSDDB(t)

	// Create a device with a heartbeat config.
	_, err := d.Exec(
		`INSERT INTO devices (name, type, ip_address, status)
		VALUES (?, ?, ?, ?)`,
		"web-01", "server", "10.0.1.10", "online",
	)
	require.NoError(t, err)
	var deviceID int64
	err = d.QueryRow("SELECT last_insert_rowid()").Scan(&deviceID)
	require.NoError(t, err)

	_, err = d.Exec(
		`INSERT INTO heartbeat_configs (device_id, method, target, interval_seconds, timeout_seconds, enabled)
		VALUES (?, 'http', 'http://10.0.1.10:8080/metrics', 30, 5, 1)`,
		deviceID,
	)
	require.NoError(t, err)

	// Create a scan task + scanner-discovered device.
	taskLabels, _ := json.Marshal(map[string]string{
		"env": "test",
	})
	_, err = d.Exec(
		`INSERT INTO scan_tasks (name, targets, cron_expr, pipeline_config, global_labels, timeout, concurrent_hosts, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
		"test-scan", "10.0.2.0/24", "0 2 * * *", "{}", string(taskLabels), 10, 5,
	)
	require.NoError(t, err)
	var taskID int64
	err = d.QueryRow("SELECT last_insert_rowid()").Scan(&taskID)
	require.NoError(t, err)

	servicesJSON, _ := json.Marshal([]map[string]string{
		{"service": "prometheus"},
	})
	_, err = d.Exec(
		`INSERT INTO scan_results (task_id, ip, alive, prometheus_detected, prometheus_url, node_exporter_detected, services)
		VALUES (?, ?, 1, 1, ?, 0, ?)`,
		taskID, "10.0.2.20", "10.0.2.20:9090", string(servicesJSON),
	)
	require.NoError(t, err)

	// Create SDHandler with nil systemRepo — scanner targets don't depend on it.
	sdHandler := handler.NewSDHandler(d, nil)

	req := httptest.NewRequest("GET", "/sd", nil)
	w := httptest.NewRecorder()
	sdHandler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var targets []handler.SDTarget
	err = json.Unmarshal(w.Body.Bytes(), &targets)
	require.NoError(t, err)

	// Should have at least heartbeat target + scanner target.
	require.GreaterOrEqual(t, len(targets), 2, "should have heartbeat + scanner targets")

	// Verify heartbeat target still present.
	var hasHeartbeat bool
	for _, tgt := range targets {
		if len(tgt.Targets) > 0 && tgt.Targets[0] == "http://10.0.1.10:8080/metrics" {
			hasHeartbeat = true
			require.Equal(t, "web-01", tgt.Labels["device_name"])
		}
	}
	require.True(t, hasHeartbeat, "heartbeat targets must still be present")

	// Verify scanner target present.
	var hasScanner bool
	for _, tgt := range targets {
		if len(tgt.Targets) > 0 && tgt.Targets[0] == "10.0.2.20:9090" {
			hasScanner = true
			require.Equal(t, "scanner", tgt.Labels["__source"])
			require.Equal(t, "test-scan", tgt.Labels["scan_task_name"])
			require.Equal(t, "test", tgt.Labels["env"])
			require.Equal(t, "prometheus", tgt.Labels["discovered_services"])
		}
	}
	require.True(t, hasScanner, "scanner targets must be present")
}

// TestSDHandler_ServeHTTP_Empty verifies the /sd endpoint returns an empty array for empty DB.
func TestSDHandler_ServeHTTP_Empty(t *testing.T) {
	d := setupSDDB(t)

	sdHandler := handler.NewSDHandler(d, nil)

	req := httptest.NewRequest("GET", "/sd", nil)
	w := httptest.NewRecorder()
	sdHandler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var targets []handler.SDTarget
	err := json.Unmarshal(w.Body.Bytes(), &targets)
	require.NoError(t, err)
	require.Empty(t, targets)
}

// TestParseJSONLabels tests the JSON label parser.
func TestParseJSONLabels(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
	}{
		{"empty string", "", nil},
		{"invalid JSON", "not-json", nil},
		{"valid JSON", `{"a":"b"}`, map[string]string{"a": "b"}},
		{"nested ignored", `{"a":1}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.ParseJSONLabels(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

// TestExtractDiscoveredServices tests the service name extraction.
func TestExtractDiscoveredServices(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"invalid JSON", "bad", ""},
		{"single service", `[{"service":"ssh"}]`, "ssh"},
		{"multiple services", `[{"service":"ssh"},{"service":"http"},{"service":"prometheus"}]`, "ssh,http,prometheus"},
		{"empty service skipped", `[{"service":"ssh"},{"service":""}]`, "ssh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.ExtractDiscoveredServices(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

