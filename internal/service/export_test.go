package service

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"

	_ "modernc.org/sqlite"
)

// setupExportTest creates an in-memory SQLite DB with all export-related tables.
func setupExportTest(t *testing.T) (*ExportService, *sql.DB) {
	t.Helper()

	dbConn, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })

	_, err = dbConn.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL DEFAULT '',
			type TEXT NOT NULL DEFAULT '',
			brand TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			location TEXT NOT NULL DEFAULT '',
			purpose TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'unknown',
			ip_address TEXT NOT NULL DEFAULT '',
			mac_address TEXT NOT NULL DEFAULT '',
			serial_number TEXT NOT NULL DEFAULT '',
			purchase_date TEXT NOT NULL DEFAULT '',
			warranty_expiry TEXT NOT NULL DEFAULT '',
			tags TEXT NOT NULL DEFAULT '',
			scan_source TEXT NOT NULL DEFAULT 'manual',
			prometheus_labels TEXT NOT NULL DEFAULT '{}',
			last_scanned_at DATETIME,
			last_scan_task_id INTEGER,
			open_ports TEXT NOT NULL DEFAULT '[]',
			detected_services TEXT NOT NULL DEFAULT '[]',
			prometheus_url TEXT NOT NULL DEFAULT '',
			node_exporter_url TEXT NOT NULL DEFAULT '',
			last_scan_rtt_ms INTEGER NOT NULL DEFAULT 0,
			scan_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(scan_attributes)),
			user_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(user_attributes)),
			scan_vendor   TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.vendor')) STORED,
			scan_mac      TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.mac')) STORED,
			scan_os       TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.os')) STORED,
			scan_hostname TEXT GENERATED ALWAYS AS (json_extract(scan_attributes, '$.hostname')) STORED,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS heartbeat_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL,
			method TEXT NOT NULL DEFAULT 'icmp',
			target TEXT NOT NULL DEFAULT '',
			interval_seconds INTEGER NOT NULL DEFAULT 60,
			timeout_seconds INTEGER NOT NULL DEFAULT 5,
			snmp_community TEXT NOT NULL DEFAULT 'public',
			snmp_oid TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS heartbeat_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL,
			config_id INTEGER NOT NULL,
			status TEXT NOT NULL DEFAULT '',
			latency_ms REAL NOT NULL DEFAULT 0,
			error_message TEXT NOT NULL DEFAULT '',
			checked_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			action TEXT NOT NULL,
			resource_type TEXT NOT NULL,
			resource_id TEXT,
			ip_address TEXT,
			user_agent TEXT,
			details TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)

	queries := db.New(dbConn)
	svc := NewExportService(queries)
	return svc, dbConn
}

// seedDevices inserts n devices into the DB.
func exportSeedDevices(t *testing.T, dbConn *sql.DB, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := dbConn.Exec(
			`INSERT INTO devices (name, type, status, ip_address, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
			"device-"+intToStr(i), "pc", "online", "10.0.0."+intToStr(i+1), time.Now(), time.Now(),
		)
		require.NoError(t, err)
	}
}

// seedHeartbeatResults inserts n heartbeat results for a device.
func exportSeedHeartbeatResults(t *testing.T, dbConn *sql.DB, deviceID int64, n int) {
	t.Helper()
	// Ensure a heartbeat config exists
	_, err := dbConn.Exec(
		`INSERT INTO heartbeat_configs (device_id, method, target, enabled, created_at, updated_at) VALUES (?, 'icmp', '10.0.0.1', 1, ?, ?)`,
		deviceID, time.Now(), time.Now(),
	)
	require.NoError(t, err)

	for i := 0; i < n; i++ {
		_, err := dbConn.Exec(
			`INSERT INTO heartbeat_results (device_id, config_id, status, latency_ms, error_message, checked_at) VALUES (?, 1, ?, ?, ?, ?)`,
			deviceID, "success", float64(i+1), "", time.Now().Add(-time.Duration(n-i)*time.Second),
		)
		require.NoError(t, err)
	}
}

// seedAuditLogs inserts n audit log entries.
func exportSeedAuditLogs(t *testing.T, dbConn *sql.DB, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := dbConn.Exec(
			`INSERT INTO audit_logs (user_id, action, resource_type, ip_address, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			int64(i%3+1), "action."+intToStr(i), "resource", "127.0.0.1", "test-agent",
			time.Now().Add(-time.Duration(n-i)*time.Minute),
		)
		require.NoError(t, err)
	}
}
func intToStr(n int) string {
	return fmt.Sprintf("%d", n)
}

// --- Devices Export ---

func TestExport_Devices_CSV(t *testing.T) {
	svc, dbConn := setupExportTest(t)
	exportSeedDevices(t, dbConn, 3)

	var buf bytes.Buffer
	err := svc.Devices(context.Background(), "csv", &buf)
	require.NoError(t, err)

	// Check UTF-8 BOM
	require.True(t, bytes.HasPrefix(buf.Bytes(), []byte{0xEF, 0xBB, 0xBF}))

	reader := csv.NewReader(&buf)
	// Skip BOM: read raw bytes and skip first 3
	bomBytes := buf.Bytes()
	_, err = reader.Read() // header row
	require.NoError(t, err)

	// Read 3 data rows
	count := 0
	for {
		_, err := reader.Read()
		if err != nil {
			break
		}
		count++
	}
	require.Equal(t, 3, count)

	// Verify header
	headerReader := csv.NewReader(bytes.NewReader(bomBytes[3:]))
	header, err := headerReader.Read()
	require.NoError(t, err)
	require.Equal(t, "id", header[0])
	require.Equal(t, "name", header[1])
}

func TestExport_Devices_JSON(t *testing.T) {
	svc, dbConn := setupExportTest(t)
	exportSeedDevices(t, dbConn, 2)

	var buf bytes.Buffer
	err := svc.Devices(context.Background(), "json", &buf)
	require.NoError(t, err)

	// Should be a valid JSON array
	var result []json.RawMessage
	decoder := json.NewDecoder(&buf)
	err = decoder.Decode(&result)
	require.NoError(t, err)
	require.Len(t, result, 2)
}

func TestExport_Devices_Empty(t *testing.T) {
	svc, _ := setupExportTest(t)

	var buf bytes.Buffer
	err := svc.Devices(context.Background(), "csv", &buf)
	require.NoError(t, err)

	// Should have BOM + header only
	bomBytes := buf.Bytes()
	require.True(t, bytes.HasPrefix(bomBytes, []byte{0xEF, 0xBB, 0xBF}))
}

func TestExport_Devices_StreamChunks(t *testing.T) {
	// Insert 2500 devices — more than chunk size of 1000
	svc, dbConn := setupExportTest(t)
	exportSeedDevices(t, dbConn, 2500)

	var buf bytes.Buffer
	err := svc.Devices(context.Background(), "csv", &buf)
	require.NoError(t, err)

	// Skip BOM and header
	bomBytes := buf.Bytes()
	headerReader := csv.NewReader(bytes.NewReader(bomBytes[3:]))
	_, err = headerReader.Read() // skip header
	require.NoError(t, err)

	count := 0
	for {
		_, err := headerReader.Read()
		if err != nil {
			break
		}
		count++
	}
	require.Equal(t, 2500, count, "should stream all 2500 devices in chunks")
}

// --- Heartbeat Results Export ---

func TestExport_HeartbeatResults_CSV(t *testing.T) {
	svc, dbConn := setupExportTest(t)
	exportSeedDevices(t, dbConn, 1)
	exportSeedHeartbeatResults(t, dbConn, 1, 3)

	var buf bytes.Buffer
	err := svc.HeartbeatResults(context.Background(), 1, "csv", &buf)
	require.NoError(t, err)

	require.True(t, bytes.HasPrefix(buf.Bytes(), []byte{0xEF, 0xBB, 0xBF}))

	bomBytes := buf.Bytes()
	reader := csv.NewReader(bytes.NewReader(bomBytes[3:]))
	header, err := reader.Read()
	require.NoError(t, err)
	require.Equal(t, "id", header[0])
	require.Equal(t, "device_id", header[1])

	count := 0
	for {
		_, err := reader.Read()
		if err != nil {
			break
		}
		count++
	}
	require.Equal(t, 3, count)
}

func TestExport_HeartbeatResults_JSON(t *testing.T) {
	svc, dbConn := setupExportTest(t)
	exportSeedDevices(t, dbConn, 1)
	exportSeedHeartbeatResults(t, dbConn, 1, 2)

	var buf bytes.Buffer
	err := svc.HeartbeatResults(context.Background(), 1, "json", &buf)
	require.NoError(t, err)

	var result []json.RawMessage
	decoder := json.NewDecoder(&buf)
	err = decoder.Decode(&result)
	require.NoError(t, err)
	require.Len(t, result, 2)
}

func TestExport_HeartbeatResults_Empty(t *testing.T) {
	svc, dbConn := setupExportTest(t)
	exportSeedDevices(t, dbConn, 1)

	var buf bytes.Buffer
	err := svc.HeartbeatResults(context.Background(), 1, "csv", &buf)
	require.NoError(t, err)

	require.True(t, bytes.HasPrefix(buf.Bytes(), []byte{0xEF, 0xBB, 0xBF}))
}

// --- Audit Logs Export ---

func TestExport_AuditLogs_CSV(t *testing.T) {
	svc, dbConn := setupExportTest(t)
	exportSeedAuditLogs(t, dbConn, 3)

	var buf bytes.Buffer
	err := svc.AuditLogs(context.Background(), "csv", &buf)
	require.NoError(t, err)

	require.True(t, bytes.HasPrefix(buf.Bytes(), []byte{0xEF, 0xBB, 0xBF}))

	bomBytes := buf.Bytes()
	reader := csv.NewReader(bytes.NewReader(bomBytes[3:]))
	header, err := reader.Read()
	require.NoError(t, err)
	require.Equal(t, "id", header[0])
	require.Equal(t, "action", header[2])

	count := 0
	for {
		_, err := reader.Read()
		if err != nil {
			break
		}
		count++
	}
	require.Equal(t, 3, count)
}

func TestExport_AuditLogs_JSON(t *testing.T) {
	svc, dbConn := setupExportTest(t)
	exportSeedAuditLogs(t, dbConn, 2)

	var buf bytes.Buffer
	err := svc.AuditLogs(context.Background(), "json", &buf)
	require.NoError(t, err)

	var result []json.RawMessage
	decoder := json.NewDecoder(&buf)
	err = decoder.Decode(&result)
	require.NoError(t, err)
	require.Len(t, result, 2)
}

func TestExport_AuditLogs_Empty(t *testing.T) {
	svc, _ := setupExportTest(t)

	var buf bytes.Buffer
	err := svc.AuditLogs(context.Background(), "csv", &buf)
	require.NoError(t, err)

	require.True(t, bytes.HasPrefix(buf.Bytes(), []byte{0xEF, 0xBB, 0xBF}))
}

// --- Format Validation ---

func TestExport_InvalidFormat_DefaultsToCSV(t *testing.T) {
	svc, dbConn := setupExportTest(t)
	exportSeedDevices(t, dbConn, 1)

	var buf bytes.Buffer
	err := svc.Devices(context.Background(), "yaml", &buf)
	require.NoError(t, err)
	require.True(t, bytes.HasPrefix(buf.Bytes(), []byte{0xEF, 0xBB, 0xBF}), "invalid format should default to CSV")
}
