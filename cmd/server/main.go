package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	dbsql "mibee-steward/db"
	"mibee-steward/internal/api/routes"
	"mibee-steward/internal/config"
	"mibee-steward/internal/service"
)

var (
	configPath = flag.String("config", "configs/config.example.yaml", "Path to config file")
	Version    = "dev"
)

func main() {
	flag.Parse()

	// Load configuration first (before slog init)
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize structured logger
	initLogger(cfg.Log)

	slog.Info("starting MiBee Steward", "version", Version)

	// Ensure data directory exists
	dbPath := cfg.Database.SQLite.Path
	if dbPath == "" {
		dbPath = "./data/mibee.db"
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		slog.Error("failed to create data directory", "error", err, "path", filepath.Dir(dbPath))
		os.Exit(1)
	}

	// Open database connection
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}

	// Configure connection pool. Was 2 (a common SQLite default), but the
	// heartbeat service's concurrent verdict writes (GetDevice + UpdateDeviceStatus
	// for up to 16 devices at once) starved on 2 connections: a verdict goroutine
	// holding failCountsMu would block on a DB read while the other connection was
	// busy writing — leaving devices stuck on offline. 16 gives the probe pool
	// enough connections to read device state without blocking the writer.
	// WAL mode keeps reads from blocking the single writer, so this is safe.
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)

	// Optimize SQLite with WAL mode
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=-64000",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			slog.Error("failed to set pragma", "pragma", p, "error", err)
			os.Exit(1)
		}
	}
	// Run migrations
	if err := runMigrations(db, dbPath); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	// Ensure upload directory exists
	if cfg.Storage.UploadPath != "" {
		if err := os.MkdirAll(cfg.Storage.UploadPath, 0755); err != nil {
			slog.Error("failed to create upload directory", "error", err, "path", cfg.Storage.UploadPath)
			os.Exit(1)
		}
	}
	// Initial admin password is required
	if cfg.Auth.InitialAdminPassword == "" {
		slog.Error("initial_admin_password must be set in config or via MIBEE_AUTH_INITIAL_ADMIN_PASSWORD env var")
		os.Exit(1)
	}
	expiry := 24 * time.Hour
	if cfg.Auth.TokenExpiry != "" {
		if d, err := time.ParseDuration(cfg.Auth.TokenExpiry); err == nil {
			expiry = d
		}
	}
	userSvc := service.NewUserService(db, cfg.Auth.JWTSecret, expiry)
	seedAdminUser(userSvc, cfg.Auth.InitialAdminPassword)

	// Create router
	router, heartbeatSvc, shutdownScanner := routes.NewRouter(db, cfg)

	// Determine bind address
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	if cfg.Server.Port == 0 {
		addr = ":8080"
	}

	// Create HTTP server. Timeouts are configurable because the synchronous
	// /scanner/scan endpoint can legitimately run for minutes on large CIDRs;
	// the previous hard-coded 60s WriteTimeout truncated those responses.
	readTO := parseDurationOrDefault(cfg.Server.ReadTimeout, 15*time.Second)
	writeTO := parseDurationOrDefault(cfg.Server.WriteTimeout, 5*time.Minute)
	idleTO := parseDurationOrDefault(cfg.Server.IdleTimeout, 120*time.Second)
	// Guard: WriteTimeout must be at least as long as the configured scanner
	// default timeout × a sane multiplier, or synchronous scans will be cut off.
	if minWrite := time.Duration(cfg.Scanner.DefaultTimeout*2+30) * time.Second; writeTO < minWrite && cfg.Scanner.DefaultTimeout > 0 {
		slog.Warn("server.write_timeout too low for synchronous scans; raising", "configured", writeTO, "raised_to", minWrite)
		writeTO = minWrite
	}
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  readTO,
		WriteTimeout: writeTO,
		IdleTimeout:  idleTO,
	}
	slog.Info("http server timeouts", "read", readTO, "write", writeTO, "idle", idleTO)

	// Start server in goroutine
	go func() {
		slog.Info("listening", "address", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server...")

	// Stop heartbeat scheduler
	heartbeatSvc.Stop()
	slog.Info("heartbeat scheduler stopped")

	// Stop scanner services
	shutdownScanner()
	slog.Info("scanner services stopped")

	// Shutdown HTTP server with 15s timeout.
	// cancel is called explicitly (not deferred) because os.Exit below would
	// skip any deferred calls, leaking the timeout context's resources.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := srv.Shutdown(ctx); err != nil {
		cancel()
		slog.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}
	cancel()

	// Close database
	db.Close()
	slog.Info("server stopped")
}

func initLogger(cfg config.LogConfig) {
	level := parseLogLevel(cfg.Level)
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	switch cfg.Format {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	default:
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func runMigrations(db *sql.DB, dbPath string) error {
	// Backup database before migration (only if file exists)
	if _, err := os.Stat(dbPath); err == nil {
		backupPath := dbPath + ".pre-migration." + time.Now().Format("20060102-150405")
		// VACUUM INTO cannot be parameterised, so sanitize the path to avoid
		// breaking the statement (or worse) if dbPath ever contains a quote /
		// semicolon. Reject anything suspicious rather than trying to escape.
		if strings.ContainsAny(backupPath, "'\";\\") {
			slog.Warn("skipping pre-migration backup: dbPath contains unsafe characters", "dbPath", dbPath)
		} else {
			if _, err := db.ExecContext(context.Background(), fmt.Sprintf("VACUUM INTO '%s'", backupPath)); err != nil {
				slog.Warn("failed to backup database before migration", "error", err)
			} else {
				slog.Info("database backed up before migration", "path", backupPath)
			}
		}
	}

	// Execute embedded schema directly
	if _, err := db.Exec(dbsql.SchemaSQL); err != nil {
		return fmt.Errorf("failed to apply schema: %w", err)
	}

	// Run idempotent column migrations (safe to re-run)
	migrations := []string{
		"ALTER TABLE devices ADD COLUMN scan_source TEXT NOT NULL DEFAULT 'manual'",
		"ALTER TABLE devices ADD COLUMN prometheus_labels TEXT NOT NULL DEFAULT '{}'",
		"ALTER TABLE devices ADD COLUMN last_scanned_at TIMESTAMP",
		"ALTER TABLE devices ADD COLUMN last_scan_task_id INTEGER",
		"ALTER TABLE devices ADD COLUMN open_ports TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE devices ADD COLUMN detected_services TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE devices ADD COLUMN prometheus_url TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE devices ADD COLUMN node_exporter_url TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE devices ADD COLUMN last_scan_rtt_ms INTEGER NOT NULL DEFAULT 0",
		// scan_results columns added in a later schema revision. DBs created
		// before those columns existed keep the stale shape because
		// CREATE TABLE IF NOT EXISTS is a no-op, so backfill them here.
		"ALTER TABLE scan_results ADD COLUMN prometheus_detected INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE scan_results ADD COLUMN prometheus_url TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE scan_results ADD COLUMN node_exporter_detected INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE scan_results ADD COLUMN node_exporter_url TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE scan_results ADD COLUMN node_exporter_data TEXT NOT NULL DEFAULT '{}'",
		// Dual JSON layer (scan_attributes + user_attributes). Generated columns
		// (scan_vendor/scan_mac/scan_os/scan_hostname) can't be added via ALTER
		// on existing DBs — those are only present on fresh installs. For
		// upgraded DBs we add expression indexes below so the json_extract
		// queries work without the generated columns.
		"ALTER TABLE devices ADD COLUMN scan_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(scan_attributes))",
		"ALTER TABLE devices ADD COLUMN user_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(user_attributes))",
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			// Ignore "duplicate column" errors — column already exists
			if !strings.Contains(err.Error(), "duplicate column name") {
				return fmt.Errorf("failed to run migration %q: %w", m, err)
			}
		}
	}

	// Backfill scan_attributes from the legacy scan-info columns on existing
	// rows that haven't been touched by the v2 engine yet (scan_attributes is
	// still the empty default '{}'). Idempotent: once a row's scan_attributes
	// is non-empty, the engine owns it and this merge won't run again.
	if _, err := db.Exec(`UPDATE devices
		SET scan_attributes = json_object(
			'open_ports',         json(open_ports),
			'detected_services',  json(detected_services),
			'prometheus',         json_object(
				'url',               prometheus_url,
				'node_exporter_url', node_exporter_url,
				'labels',            json(prometheus_labels)
			),
			'scan_source',        scan_source,
			'last_scan_rtt_ms',   last_scan_rtt_ms,
			'last_scanned_at',    COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', last_scanned_at), '')
		)
		WHERE scan_attributes = '{}'`); err != nil {
		// Non-fatal: legacy rows just won't be back-filled; new scans populate
		// scan_attributes directly. Log and continue.
		slog.Warn("scan_attributes backfill failed", "error", err)
	}

	// Expression indexes (work on existing DBs without the generated columns).
	// Safe to re-run via IF NOT EXISTS.
	for _, idx := range []string{
		`CREATE INDEX IF NOT EXISTS idx_devices_scan_mac_expr    ON devices(json_extract(scan_attributes, '$.mac'))`,
		`CREATE INDEX IF NOT EXISTS idx_devices_scan_vendor_expr ON devices(json_extract(scan_attributes, '$.vendor'))`,
	} {
		if _, err := db.Exec(idx); err != nil {
			// Some SQLite builds gate expression indexes behind a compile flag;
			// absence just means slower MAC/vendor lookups, not a failure.
			slog.Warn("scan_attributes expression index creation skipped", "index", idx, "error", err)
		}
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			// Ignore "duplicate column" errors — column already exists
			if !strings.Contains(err.Error(), "duplicate column name") {
				return fmt.Errorf("failed to run migration %q: %w", m, err)
			}
		}
	}

	// Idempotent constraint/index migrations. These enforce uniqueness invariants
	// the application code already assumes but the original schema didn't guard.
	// Existing rows are de-duplicated first so CREATE UNIQUE INDEX can't fail on
	// a long-running DB that accumulated dupes via the original (un-guarded) path.
	if err := applyUniqueIndexMigrations(context.Background(), db); err != nil {
		return fmt.Errorf("unique-index migrations: %w", err)
	}

	// Extend scan_task_runs.status CHECK to include 'cancelled' (used by the
	// cancel endpoint). SQLite can't ALTER a CHECK in place, so on existing DBs
	// we rebuild the table; the fresh-install path is already handled by
	// schema.sql. Idempotent: skips the rebuild if 'cancelled' is already allowed.
	if err := extendScanRunStatusCheck(context.Background(), db); err != nil {
		return fmt.Errorf("scan_task_runs status migration: %w", err)
	}

	// Add the scan_attributes generated columns (scan_vendor/scan_mac/scan_os/
	// scan_hostname) to existing DBs. SQLite can't ALTER ADD COLUMN with a
	// non-constant expression, so a table rebuild is required. Fresh installs
	// already get them from schema.sql; this is a no-op there.
	if err := addDevicesGeneratedColumns(context.Background(), db); err != nil {
		return fmt.Errorf("devices generated-columns migration: %w", err)
	}

	slog.Info("database schema applied")
	return nil
}

// addDevicesGeneratedColumns adds the scan_attributes-derived generated columns
// (scan_vendor/scan_mac/scan_os/scan_hostname) to existing DBs via SQLite's
// 12-step table rebuild. SQLite disallows ALTER TABLE ADD COLUMN with a
// non-constant generated expression, so the rebuild is the only path.
//
// Idempotent: if scan_mac already exists (fresh install, or already rebuilt),
// this is a no-op. FK references to devices(id) in heartbeat_configs,
// device_systems, and device_documents are preserved by name through the
// rename (SQLite resolves FK by table name, not by internal rootpage).
func addDevicesGeneratedColumns(ctx context.Context, db *sql.DB) error {
	// Idempotency probe: does scan_mac already exist? Note that the older
	// pragma_table_info HIDES generated columns — pragma_table_xinfo is the
	// only pragma that surfaces them. Use it here so the rebuild doesn't run
	// on every startup.
	var ignore string
	err := db.QueryRowContext(ctx,
		`SELECT name FROM pragma_table_xinfo('devices') WHERE name = 'scan_mac' LIMIT 1`,
	).Scan(&ignore)
	if err == nil {
		// Column already present — nothing to do.
		return nil
	}
	if !strings.Contains(err.Error(), "no rows") {
		return fmt.Errorf("probe devices.scan_mac: %w", err)
	}

	slog.Info("rebuilding devices table to add scan_attributes generated columns")

	// Rebuild preserving the FULL current column set plus the 4 new generated
	// columns. We list every column from schema.sql's CREATE TABLE so the copy
	// is shape-identical (no data loss, no type drift). GENERATED ALWAYS AS
	// columns are NOT copied explicitly — SQLite derives them on insert from
	// the scan_attributes value being copied.
	stmts := []string{
		`CREATE TABLE devices_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'other' CHECK(type IN ('pc', 'embedded', 'iot', 'other', 'server', 'switch', 'router', 'firewall', 'nas', 'camera')),
			brand TEXT NOT NULL DEFAULT '',
			model TEXT NOT NULL DEFAULT '',
			location TEXT NOT NULL DEFAULT '',
			purpose TEXT NOT NULL DEFAULT '',
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'unknown' CHECK(status IN ('online', 'offline', 'unknown')),
			ip_address TEXT NOT NULL DEFAULT '',
			mac_address TEXT NOT NULL DEFAULT '',
			serial_number TEXT NOT NULL DEFAULT '',
			purchase_date TEXT NOT NULL DEFAULT '',
			warranty_expiry TEXT NOT NULL DEFAULT '',
			tags TEXT NOT NULL DEFAULT '{}',
			scan_source TEXT NOT NULL DEFAULT 'manual',
			prometheus_labels TEXT NOT NULL DEFAULT '{}',
			last_scanned_at TIMESTAMP,
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
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO devices_new (id, name, type, brand, model, location, purpose, description,
			status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags,
			scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports,
			detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms,
			scan_attributes, user_attributes, created_at, updated_at)
		SELECT id, name, type, brand, model, location, purpose, description,
			status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags,
			scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports,
			detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms,
			scan_attributes, user_attributes, created_at, updated_at FROM devices`,
		`DROP TABLE devices`,
		`ALTER TABLE devices_new RENAME TO devices`,
		// Re-create the indexes that existed on the original devices table.
		`CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status)`,
		`CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(type)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip_address ON devices(ip_address)`,
		`CREATE INDEX IF NOT EXISTS idx_devices_scan_mac_expr    ON devices(json_extract(scan_attributes, '$.mac'))`,
		`CREATE INDEX IF NOT EXISTS idx_devices_scan_vendor_expr ON devices(json_extract(scan_attributes, '$.vendor'))`,
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin devices rebuild tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// FK enforcement off for the rebuild (we're recreating the parent table;
	// child rows in heartbeat_configs/device_systems/device_documents would
	// otherwise fail the FK check mid-rebuild because the parent briefly
	// doesn't exist). Re-enabled when the connection's next transaction opens
	// (SQLite resets it per-transaction under WAL).
	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return fmt.Errorf("disable FKs for rebuild: %w", err)
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("devices rebuild step failed: %w (stmt: %s)", err, s)
		}
	}
	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("re-enable FKs after rebuild: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit devices rebuild: %w", err)
	}
	slog.Info("devices table rebuilt with scan_attributes generated columns")
	return nil
}

// applyUniqueIndexMigrations de-duplicates rows then creates UNIQUE indexes on
// devices(ip_address) and heartbeat_configs(device_id, method). Safe to re-run.
func applyUniqueIndexMigrations(ctx context.Context, db *sql.DB) error {
	// devices.ip_address — keep the lowest id per ip_address, delete the rest.
	// Empty ip_address ('') is treated as "no IP" and left alone (many rows may
	// legitimately have no IP, e.g. manually-added devices without one).
	if _, err := db.ExecContext(ctx, `DELETE FROM devices WHERE id NOT IN (
		SELECT MIN(id) FROM devices WHERE ip_address != '' GROUP BY ip_address
	) AND ip_address != '' AND ip_address IN (
		SELECT ip_address FROM devices WHERE ip_address != ''
		GROUP BY ip_address HAVING COUNT(*) > 1
	)`); err != nil {
		// Non-fatal: log and continue; the index creation below will surface a
		// hard failure if dupes actually remain.
		slog.Warn("devices ip_address de-dup sweep failed", "error", err)
	}
	if _, err := db.ExecContext(ctx,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip_address ON devices(ip_address)`); err != nil {
		return fmt.Errorf("create idx_devices_ip_address: %w", err)
	}

	// heartbeat_configs(device_id, method) — keep the lowest id per pair.
	if _, err := db.ExecContext(ctx, `DELETE FROM heartbeat_configs WHERE id NOT IN (
		SELECT MIN(id) FROM heartbeat_configs GROUP BY device_id, method
	)`); err != nil {
		slog.Warn("heartbeat_configs de-dup sweep failed", "error", err)
	}
	if _, err := db.ExecContext(ctx,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_heartbeat_configs_device_method ON heartbeat_configs(device_id, method)`); err != nil {
		return fmt.Errorf("create idx_heartbeat_configs_device_method: %w", err)
	}
	return nil
}

// extendScanRunStatusCheck rebuilds scan_task_runs to include 'cancelled' in the
// status CHECK constraint. SQLite cannot ALTER a CHECK in place, so the standard
// 12-step table-rebuild is used (create new → copy → drop old → rename).
// Idempotent: if 'cancelled' is already an allowed status, this is a no-op.
func extendScanRunStatusCheck(ctx context.Context, db *sql.DB) error {
	// Probe whether the current CHECK already accepts 'cancelled' by inserting
	// (and rolling back) a sentinel row. FK to scan_tasks(id)=0 would normally
	// fail, so disable FK enforcement for the probe transaction only.
	probe, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin probe tx: %w", err)
	}
	probeErr := func() error {
		if _, err := probe.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
			return err
		}
		_, err := probe.ExecContext(ctx,
			`INSERT INTO scan_task_runs (task_id, status) VALUES (0, 'cancelled')`)
		return err
	}()
	_ = probe.Rollback()
	if probeErr == nil {
		// CHECK already permits 'cancelled' — nothing to do.
		return nil
	}
	if !strings.Contains(probeErr.Error(), "CHECK constraint failed") {
		// Unexpected probe error — surface it rather than rebuilding blindly.
		return fmt.Errorf("probe scan_task_runs CHECK: %w", probeErr)
	}

	slog.Info("rebuilding scan_task_runs to add 'cancelled' status")
	// Rebuild via temp table (SQLite's recommended table-rebuild pattern).
	stmts := []string{
		`CREATE TABLE scan_task_runs_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id INTEGER NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
			status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
			total_hosts INTEGER NOT NULL DEFAULT 0,
			alive_hosts INTEGER NOT NULL DEFAULT 0,
			new_hosts INTEGER NOT NULL DEFAULT 0,
			updated_hosts INTEGER NOT NULL DEFAULT 0,
			duration_ms INTEGER NOT NULL DEFAULT 0,
			error_message TEXT NOT NULL DEFAULT '',
			started_at TIMESTAMP,
			finished_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO scan_task_runs_new (id, task_id, status, total_hosts, alive_hosts, new_hosts, updated_hosts, duration_ms, error_message, started_at, finished_at, created_at)
		 SELECT id, task_id, status, total_hosts, alive_hosts, new_hosts, updated_hosts, duration_ms, error_message, started_at, finished_at, created_at FROM scan_task_runs`,
		`DROP TABLE scan_task_runs`,
		`ALTER TABLE scan_task_runs_new RENAME TO scan_task_runs`,
		`CREATE INDEX IF NOT EXISTS idx_scan_task_runs_task ON scan_task_runs(task_id)`,
		`CREATE INDEX IF NOT EXISTS idx_scan_task_runs_status ON scan_task_runs(status)`,
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin rebuild tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("rebuild step failed: %w (stmt: %s)", err, s)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit rebuild: %w", err)
	}
	slog.Info("scan_task_runs rebuilt with 'cancelled' status")
	return nil
}

func seedAdminUser(userSvc *service.UserService, password string) {
	ctx := context.Background()
	if _, err := userSvc.Register(ctx, "admin", "admin@localhost", password, "admin"); err != nil {
		if err == service.ErrUserExists {
			slog.Info("admin user already exists, skipping seed")
			return
		}
		slog.Warn("failed to seed admin user", "error", err)
		return
	}
	// Force admin to change password on first login
	if err := userSvc.SetMustChangePassword(ctx, 1, true); err != nil {
		slog.Warn("failed to set must_change_password for admin", "error", err)
	}
	slog.Info("default admin user created", "username", "admin")
}

// parseDurationOrDefault parses a config duration string (e.g. "5m", "30s"),
// returning def on empty/parse-error with a logged warning.
func parseDurationOrDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		slog.Warn("invalid duration in config, using default", "value", s, "default", def, "error", err)
		return def
	}
	return d
}
