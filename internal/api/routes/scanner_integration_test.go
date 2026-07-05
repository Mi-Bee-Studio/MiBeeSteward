package routes

import (
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"mibee-steward/internal/config"
)

func newTestConfig() *config.Config {
	return &config.Config{
		Auth: config.AuthConfig{
			JWTSecret: "test-jwt-secret-key-that-is-at-least-32-chars-long-for-testing",
		},
		Server: config.ServerConfig{
			Port: 0,
		},
		Scanner: config.ScannerConfig{
			MaxConcurrentHosts: 10,
			RetentionDays:      7,
		},
	}
}

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open in-memory db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Apply schema
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			ip_address TEXT,
			type TEXT DEFAULT 'unknown',
			brand TEXT DEFAULT '',
			model TEXT DEFAULT '',
			location TEXT DEFAULT '',
			purpose TEXT DEFAULT '',
			description TEXT DEFAULT '',
			status TEXT DEFAULT 'unknown',
			mac_address TEXT DEFAULT '',
			serial_number TEXT DEFAULT '',
			purchase_date TEXT DEFAULT '',
			warranty_expiry TEXT DEFAULT '',
			tags TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS scan_tasks (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			targets TEXT NOT NULL,
			cron_expr TEXT DEFAULT '',
			pipeline_config TEXT DEFAULT '{}',
			global_labels TEXT DEFAULT '',
			timeout INTEGER DEFAULT 300,
			concurrent_hosts INTEGER DEFAULT 50,
			enabled INTEGER DEFAULT 1,
			last_run_status TEXT DEFAULT '',
			last_run_at TIMESTAMP DEFAULT NULL,
			next_run_at TIMESTAMP DEFAULT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS scan_task_runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id INTEGER NOT NULL,
			status TEXT DEFAULT 'running',
			total_hosts INTEGER DEFAULT 0,
			alive_hosts INTEGER DEFAULT 0,
			new_hosts INTEGER DEFAULT 0,
			updated_hosts INTEGER DEFAULT 0,
			duration_ms INTEGER DEFAULT 0,
			error_message TEXT DEFAULT '',
			started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			finished_at TIMESTAMP DEFAULT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (task_id) REFERENCES scan_tasks(id)
		);
		CREATE TABLE IF NOT EXISTS scan_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id INTEGER NOT NULL,
			run_id INTEGER DEFAULT NULL,
			ip TEXT NOT NULL,
			alive INTEGER DEFAULT 0,
			rtt_ms INTEGER DEFAULT 0,
			ports TEXT DEFAULT '[]',
			services TEXT DEFAULT '{}',
			snmp_data TEXT DEFAULT '{}',
			prometheus_detected INTEGER DEFAULT 0,
			prometheus_url TEXT DEFAULT '',
			node_exporter_detected INTEGER DEFAULT 0,
			node_exporter_url TEXT DEFAULT '',
			node_exporter_data TEXT DEFAULT '',
			scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (task_id) REFERENCES scan_tasks(id),
			FOREIGN KEY (run_id) REFERENCES scan_task_runs(id)
		);
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT DEFAULT 'user',
			must_change_password INTEGER DEFAULT 0,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			action TEXT NOT NULL,
			resource_type TEXT DEFAULT '',
			resource_id INTEGER DEFAULT 0,
			details TEXT DEFAULT '',
			ip_address TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);
		CREATE TABLE IF NOT EXISTS device_systems (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			system_type TEXT DEFAULT 'other',
			entry_url TEXT DEFAULT '',
			description TEXT DEFAULT '',
			FOREIGN KEY (device_id) REFERENCES devices(id)
		);
		CREATE TABLE IF NOT EXISTS documents (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT DEFAULT 'file',
			content TEXT DEFAULT '',
			device_id INTEGER DEFAULT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (device_id) REFERENCES devices(id)
		);
		CREATE TABLE IF NOT EXISTS device_documents (
			device_id INTEGER NOT NULL,
			document_id INTEGER NOT NULL,
			PRIMARY KEY (device_id, document_id),
			FOREIGN KEY (device_id) REFERENCES devices(id),
			FOREIGN KEY (document_id) REFERENCES documents(id)
		);
		CREATE TABLE IF NOT EXISTS heartbeat_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER NOT NULL UNIQUE,
			interval_seconds INTEGER DEFAULT 60,
			method TEXT DEFAULT 'icmp',
			timeout INTEGER DEFAULT 5,
			port INTEGER DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			failure_threshold INTEGER DEFAULT 3,
			community TEXT DEFAULT 'public',
			oid TEXT DEFAULT '1.3.6.1.2.1.1.0',
			url TEXT DEFAULT '',
			expected_status INTEGER DEFAULT 200,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (device_id) REFERENCES devices(id)
		);
		CREATE TABLE IF NOT EXISTS heartbeat_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			config_id INTEGER NOT NULL,
			device_id INTEGER NOT NULL,
			status TEXT DEFAULT 'unknown',
			latency_ms INTEGER DEFAULT 0,
			error_message TEXT DEFAULT '',
			checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (config_id) REFERENCES heartbeat_configs(id),
			FOREIGN KEY (device_id) REFERENCES devices(id)
		);
		CREATE TABLE IF NOT EXISTS notification_channels (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			config TEXT DEFAULT '{}',
			enabled INTEGER DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS alert_rules (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			channel_id INTEGER NOT NULL,
			condition TEXT DEFAULT '{}',
			enabled INTEGER DEFAULT 1,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (channel_id) REFERENCES notification_channels(id)
		);
		CREATE TABLE IF NOT EXISTS notification_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			channel_id INTEGER,
			rule_id INTEGER,
			device_id INTEGER,
			status TEXT DEFAULT '',
			message TEXT DEFAULT '',
			error TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (channel_id) REFERENCES notification_channels(id),
			FOREIGN KEY (rule_id) REFERENCES alert_rules(id),
			FOREIGN KEY (device_id) REFERENCES devices(id)
		);
		CREATE TABLE IF NOT EXISTS dashboard_configs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			config TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		t.Fatalf("failed to create schema: %v", err)
	}

	return db
}

// TestScannerIntegration verifies that NewRouter initializes scanner services
// and returns a valid HTTP handler and shutdown function without panicking.
func TestScannerIntegration(t *testing.T) {
	cfg := newTestConfig()
	db := newTestDB(t)

	handler, heartbeatSvc, shutdownScanner := NewRouter(db, cfg)

	if handler == nil {
		t.Fatal("expected non-nil HTTP handler")
	}
	if heartbeatSvc == nil {
		t.Fatal("expected non-nil HeartbeatService")
	}
	if shutdownScanner == nil {
		t.Fatal("expected non-nil scanner shutdown function")
	}

	// Shutdown should not panic
	heartbeatSvc.Stop()
	shutdownScanner()
}

// TestScannerShutdownIdempotent verifies that calling the scanner shutdown
// function multiple times does not panic.
func TestScannerShutdownIdempotent(t *testing.T) {
	cfg := newTestConfig()
	db := newTestDB(t)

	_, heartbeatSvc, shutdownScanner := NewRouter(db, cfg)

	// Call shutdown twice — should not panic
	shutdownScanner()
	shutdownScanner()

	heartbeatSvc.Stop()
}

// TestScannerServicesStart verifies that scanner background services
// can be started and stopped within a short time window (race-free).
func TestScannerServicesStart(t *testing.T) {
	cfg := newTestConfig()
	db := newTestDB(t)

	_, _, shutdownScanner := NewRouter(db, cfg)

	// Give services a moment to start, then shut down
	time.Sleep(100 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		shutdownScanner()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("scanner shutdown timed out")
	}
}
