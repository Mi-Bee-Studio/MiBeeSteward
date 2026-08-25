// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. A commercial license is available for use cases
// the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Database migration functions, extracted from main.go to keep that file
// focused on startup/wiring. All migrations are idempotent (CREATE TABLE IF
// NOT EXISTS + ALTER TABLE guarded by "duplicate column" error checks + table
// rebuilds for CHECK/generated-column changes). A pre-migration VACUUM INTO
// backup is taken automatically on existing DBs. (#157)

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	dbsql "mibee-steward/db"
	"mibee-steward/internal/service/scannerv2/taskservice"
)

// SchemaVersion is the current schema generation, stored in
// PRAGMA user_version (#268). Bump it when adding a migration step to the
// chain below; existing databases replay only when their recorded version is
// lower (every step stays idempotent regardless, so a v0 database from before
// this framework simply runs the whole chain once and gets stamped).
const SchemaVersion = 1

func runMigrations(db *sql.DB, dbPath string) error {
	// Version gate (#268): a database already at SchemaVersion skips the whole
	// chain — no pre-migration VACUUM INTO backup (previously taken on EVERY
	// startup), no probe statements, no rebuild checks. Startup goes from
	// "hundreds of idempotent statements" to one PRAGMA read.
	var current int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	switch {
	case current == SchemaVersion:
		slog.Info("schema already at version; migrations skipped",
			"version", current)
		return nil
	case current > SchemaVersion:
		// Downgraded binary against a newer schema. The chain below is
		// idempotent but written for forward migration only — refuse rather
		// than touch a newer database.
		slog.Warn("database schema version is NEWER than this binary; skipping migrations",
			"db_version", current, "binary_version", SchemaVersion)
		return nil
	}
	slog.Info("running schema migrations", "from_version", current, "to_version", SchemaVersion)

	// Backup database before migration (only if file exists) — now taken only
	// when a migration will actually run (version gate above), not every boot.
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
		// Prune pre-migration backups older than 7 days (#257): every startup
		// takes one, and nothing cleaned them up — the field showed dozens of
		// accumulating multi-hundred-MB copies next to the live DB. The
		// scripts/backup.sh 7-day retention covers its own files, not these.
		pruneOldBackups(filepath.Dir(dbPath), filepath.Base(dbPath)+".pre-migration.", 7*24*time.Hour)
	}
	// Count-based retention (#268): keep at most the 3 newest pre-migration
	// backups regardless of age — a 7-day window still piles up ~50 copies on
	// a daily-restart deployment, and each is a full multi-hundred-MB VACUUM.
	pruneExcessBackups(filepath.Dir(dbPath), filepath.Base(dbPath)+".pre-migration.", 3)

	// Pre-schema ALTERs (#268): schema.sql now carries idx_devices_ip_network
	// and idx_scan_tasks_network, which reference the network_id columns that
	// LEGACY databases only get from the migration chain below. Adding them
	// before the schema apply lets both paths (fresh: schema.sql creates them
	// inline; legacy: added here) satisfy the indexes. On a fresh empty DB
	// both statements fail with "no such table" — tolerated, schema.sql
	// creates everything a moment later.
	for _, stmt := range []string{
		`ALTER TABLE devices ADD COLUMN network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL`,
		`ALTER TABLE scan_tasks ADD COLUMN network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			msg := err.Error()
			if !strings.Contains(msg, "duplicate column name") && !strings.Contains(msg, "no such table") {
				return fmt.Errorf("pre-schema migration %q: %w", stmt, err)
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
		// scan_snapshots flap state (lease-sweeper debounce for intermittently-seen
		// agent devices). flap_count counts liveness transitions; last_flap_at ages
		// them out after a stable period. See db/schema.sql scan_snapshots.
		"ALTER TABLE scan_snapshots ADD COLUMN flap_count INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE scan_snapshots ADD COLUMN last_flap_at DATETIME",
		// Synthetic device identity (device_uuid): a stable, IP-independent key so
		// satellite tables can follow a device across DHCP roams. Added nullable
		// (DEFAULT ''); backfilled + indexed in a later migration step, then the
		// IP-keyed satellite tables are re-keyed onto device_uuid. See the device
		// identity rearchitecture plan.
		"ALTER TABLE devices ADD COLUMN device_uuid TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE scan_snapshots ADD COLUMN device_uuid TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE host_services ADD COLUMN device_uuid TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE service_evidence ADD COLUMN device_uuid TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE host_tls_certs ADD COLUMN device_uuid TEXT NOT NULL DEFAULT ''",
		// offline_since: stamped when a device flips to 'offline' (all heartbeat
		// configs failed, or lost-detection/lease-sweeper marked it gone), cleared
		// on recovery. Drives the silent-device retention sweep (issue #117). The
		// backfill below approximates it for existing offline devices from
		// updated_at (the last status write).
		"ALTER TABLE devices ADD COLUMN offline_since TIMESTAMP",
		// ssh_credential_id: binds a device to an SSH credential for the config-
		// backup probe (#137). NULL = not config-backed-up. SET NULL on credential
		// delete so the device row survives (backup just pauses for it).
		"ALTER TABLE devices ADD COLUMN ssh_credential_id INTEGER REFERENCES ssh_credentials(id) ON DELETE SET NULL",
		// documents.deleted_at: soft-delete tombstone backing the UI's
		// delete-undo (POST /documents/{id}/restore). Reads filter on it; the
		// uploaded file stays on disk so restore is lossless.
		"ALTER TABLE documents ADD COLUMN deleted_at TIMESTAMP",
		// Dual JSON layer (scan_attributes + user_attributes). Generated columns
		// (scan_vendor/scan_mac/scan_os/scan_hostname) can't be added via ALTER
		// on existing DBs — those are only present on fresh installs. For
		// upgraded DBs we add expression indexes below so the json_extract
		// queries work without the generated columns.
		"ALTER TABLE devices ADD COLUMN scan_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(scan_attributes))",
		"ALTER TABLE devices ADD COLUMN user_attributes TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(user_attributes))",
		// Distributed/topology groundwork: device origin (network_id) + online
		// freshness timestamps (first_seen/last_seen). See db/schema.sql and
		// docs/private/architecture-future.md §6. network_id resolves to a
		// networks row seeded at startup (routes) from config `network`.
		"ALTER TABLE devices ADD COLUMN network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL",
		"ALTER TABLE devices ADD COLUMN first_seen TIMESTAMP",
		"ALTER TABLE devices ADD COLUMN last_seen TIMESTAMP",
		// SNMPv3 support (issue #135): bind a scan task to an SNMP credential
		// row. NULL = use the engine's global default (v1/v2c community). The
		// snmp_credentials table itself is created via schema.sql's CREATE TABLE
		// IF NOT EXISTS above (run before this loop), so the FK target exists.
		"ALTER TABLE scan_tasks ADD COLUMN credential_id INTEGER REFERENCES snmp_credentials(id) ON DELETE SET NULL",
		// Object-level scope key for the scanner surfaces (#138 Phase 2c).
		// Nullable; stamped at task create/update when the targets resolve to a
		// single networks.cidr, and backfilled below. Runs and results scope
		// through their task — they carry no network_id of their own.
		"ALTER TABLE scan_tasks ADD COLUMN network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL",
		// Probe multi-vantage groundwork (#277 step 1): execution-plan vantage
		// on targets ('center' | 'agent:{id}' | 'all'), per-vantage result
		// tracks on results. Existing rows backfill to 'center' via the
		// DEFAULT — exactly what they are today (engine-run on the center).
		// The new results index (idx_probe_results_target_vantage_time) comes
		// from schema.sql's CREATE INDEX IF NOT EXISTS, which re-runs above.
		"ALTER TABLE probe_targets ADD COLUMN vantage TEXT NOT NULL DEFAULT 'center'",
		"ALTER TABLE probe_results ADD COLUMN vantage TEXT NOT NULL DEFAULT 'center'",
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

	// Backfill device_uuid on existing devices rows (synthetic stable identity).
	// Fresh installs get device_uuid from schema.sql's DEFAULT '' but it stays
	// empty until this runs; new device creation also generates one going forward.
	// Must run BEFORE applyUniqueIndexMigrations so the UUID unique index has no
	// empty-string collisions.
	if err := backfillDeviceUUIDs(context.Background(), db); err != nil {
		return fmt.Errorf("backfill device_uuid: %w", err)
	}

	// One-shot IP-join backfill of device_uuid on the IP-keyed satellite tables.
	// At migration time every satellite row's IP matches its device's current IP
	// (both written by the same scan), so the IP-join is reliable HERE even though
	// it's exactly what breaks on DHCP roam. After this, future writes use the
	// new device-keyed upsert paths. Unmatched rows (no device) keep '' and age
	// out via retention sweeps.
	if err := backfillSatelliteUUIDs(context.Background(), db); err != nil {
		return fmt.Errorf("backfill satellite device_uuid: %w", err)
	}

	// Backfill offline_since for existing offline devices (issue #117). The column
	// was just added (nullable, all-NULL). For rows already 'offline' we approximate
	// the flip time from updated_at — the last status write, which is the closest
	// available proxy for when the device went offline. Online/unknown rows stay
	// NULL (they're not offline). Idempotent: only fills NULLs on offline rows.
	if err := backfillOfflineSince(context.Background(), db); err != nil {
		return fmt.Errorf("backfill offline_since: %w", err)
	}

	// Merge duplicate-MAC device rows (the device-split symptom): when the same
	// MAC ended up in multiple devices rows (created via the mac='' placeholder
	// hole or manual add), collapse them into one canonical row and re-point the
	// child tables. Runs at startup; idempotent (no-op once merged).
	if err := mergeDuplicateMACDevices(context.Background(), db); err != nil {
		return fmt.Errorf("merge duplicate-MAC devices: %w", err)
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

	// Widen notification_channels' type CHECK to the chat-platform family
	// (#284: feishu/wecom/telegram/discord). Same probe-first rebuild pattern.
	if err := extendNotificationChannelTypeCheck(context.Background(), db); err != nil {
		return fmt.Errorf("notification_channels type migration: %w", err)
	}

	// Add the scan_attributes generated columns (scan_vendor/scan_mac/scan_os/
	// scan_hostname) to existing DBs. SQLite can't ALTER ADD COLUMN with a
	// non-constant expression, so a table rebuild is required. Fresh installs
	// already get them from schema.sql; this is a no-op there. The rebuild
	// DROPs and recreates the devices table, which wipes ALL indexes — so the
	// distributed-identity index migration MUST run after this.
	if err := addDevicesGeneratedColumns(context.Background(), db); err != nil {
		return fmt.Errorf("devices generated-columns migration: %w", err)
	}

	// Extend devices.type CHECK to include 'phone' and 'printer' (new device
	// types). SQLite can't ALTER a CHECK in place, so on existing DBs we rebuild
	// the table; fresh installs already get the wider CHECK from schema.sql.
	// Idempotent: skips the rebuild if 'phone' is already allowed. MUST run after
	// addDevicesGeneratedColumns (same table) and before applyIdentityIndexMigrations
	// (which recreates the composite-unique index the rebuild drops).
	if err := extendDevicesTypeCheck(context.Background(), db); err != nil {
		return fmt.Errorf("devices type-check migration: %w", err)
	}

	// Extend users.role CHECK to include 'operator' and 'viewer' (RBAC capability
	// graph, #138). SQLite can't ALTER a CHECK in place, so on existing DBs we
	// rebuild the table; fresh installs already get the wider CHECK from
	// schema.sql. Idempotent: skips the rebuild if 'operator' is already allowed.
	// Purely additive — no route grants the new roles new access yet.
	if err := extendUsersRoleCheck(context.Background(), db); err != nil {
		return fmt.Errorf("users role-check migration: %w", err)
	}

	// #138 Phase 2c: backfill scan_tasks.network_id from targets→networks.cidr
	// so existing tasks slot into the object-level scope. Idempotent —
	// unresolvable tasks (multi-CIDR/range/hostname targets) stay NULL on
	// every run, harmlessly. The network_id index is created here too (after
	// the ALTER above), not in schema.sql — on old DBs scan_tasks lacks the
	// column until this point, so an index in schema.sql would fail to apply.
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_scan_tasks_network ON scan_tasks(network_id)`); err != nil {
		return fmt.Errorf("scan-tasks network index: %w", err)
	}
	if err := backfillScanTaskNetworks(context.Background(), db); err != nil {
		return fmt.Errorf("scan-task network backfill: %w", err)
	}

	// Distributed-identity index migration: replace the legacy global-unique
	// devices(ip_address) index with the (ip_address, network_id) composite +
	// MAC lookup index. Runs LAST (after the devices rebuild) so the indexes
	// survive on the final table shape. The rebuild already drops the legacy
	// idx_devices_ip_address; the DROP IF EXISTS here is a belt-and-suspenders
	// for fresh installs that never rebuilt.
	if err := applyIdentityIndexMigrations(context.Background(), db); err != nil {
		return fmt.Errorf("identity-index migrations: %w", err)
	}

	// #247: dashboard_configs.position was TEXT ('{}' default) while every
	// consumer of the value (API JSON, frontend numeric sort, drag-persist)
	// treats it as an integer. Rebuild the table with an INTEGER column on
	// existing DBs; fresh installs already get it from schema.sql.
	if err := convertDashboardConfigPosition(context.Background(), db); err != nil {
		return fmt.Errorf("dashboard-config position migration: %w", err)
	}

	// #257: the raw-SQL store layer bound Go time.Time values, which
	// modernc.org/sqlite serializes as Go's String() ("2026-08-21 06:19:41.62
	// +0000 UTC") — SQLite date()/datetime() return NULL on that form, and
	// text comparisons against the RFC3339 cutoffs misorder. Writes now go
	// through scannerv2.DBTime (RFC3339); convert existing rows in place.
	// Idempotent: the WHERE matches only the legacy Go-format suffix.
	for _, m := range []struct{ table, col string }{
		{"devices", "created_at"}, {"devices", "updated_at"},
		{"devices", "first_seen"}, {"devices", "last_seen"},
		{"devices", "last_scanned_at"}, {"devices", "offline_since"},
		{"device_neighbors", "first_seen"}, {"device_neighbors", "last_seen"},
		{"host_tls_certs", "updated_at"},
		{"scan_snapshots", "last_seen_at"}, {"scan_snapshots", "last_flap_at"},
		{"host_services", "updated_at"},
		{"service_evidence", "observed_at"},
	} {
		stmt := fmt.Sprintf(
			"UPDATE %s SET %s = replace(substr(%s, 1, 19), ' ', 'T') || 'Z' WHERE %s LIKE '%% UTC'",
			m.table, m.col, m.col, m.col)
		res, err := db.Exec(stmt)
		if err != nil {
			return fmt.Errorf("migrate timestamps %s.%s: %w", m.table, m.col, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			slog.Info("timestamp format migrated to RFC3339", "table", m.table, "column", m.col, "rows", n)
		}
	}

	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion)); err != nil {
		return fmt.Errorf("stamp schema version %d: %w", SchemaVersion, err)
	}
	slog.Info("database schema applied", "version", SchemaVersion)
	return nil
}

// pruneExcessBackups deletes the oldest backups matching prefix until at most
// keep remain. Backup filenames carry a sortable timestamp, so lexical order
// is age order. Best-effort, like pruneOldBackups.
func pruneExcessBackups(dir, prefix string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var matches []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			matches = append(matches, e.Name())
		}
	}
	if len(matches) <= keep {
		return
	}
	sort.Strings(matches) // oldest (lexically smallest timestamp) first
	for _, name := range matches[:len(matches)-keep] {
		if err := os.Remove(filepath.Join(dir, name)); err == nil {
			slog.Info("pruned excess pre-migration backup", "file", name, "kept", keep)
		}
	}
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
			type TEXT NOT NULL DEFAULT 'other' CHECK(type IN ('pc', 'embedded', 'iot', 'other', 'server', 'switch', 'router', 'firewall', 'nas', 'camera', 'phone', 'printer')),
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
			network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
			first_seen TIMESTAMP,
			last_seen TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO devices_new (id, name, type, brand, model, location, purpose, description,
			status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags,
			scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports,
			detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms,
			scan_attributes, user_attributes, network_id, first_seen, last_seen, created_at, updated_at)
		SELECT id, name, type, brand, model, location, purpose, description,
			status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags,
			scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports,
			detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms,
			scan_attributes, user_attributes, network_id, first_seen, last_seen, created_at, updated_at FROM devices`,
		`DROP TABLE devices`,
		`ALTER TABLE devices_new RENAME TO devices`,
		// Re-create the indexes that existed on the original devices table.
		// NOTE: the old global-unique idx_devices_ip_address is intentionally NOT
		// recreated here — applyIdentityIndexMigrations replaces it with the
		// (ip_address, network_id) composite-unique index needed for distributed
		// (multi-LAN) deployments. See applyIdentityIndexMigrations.
		`CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status)`,
		`CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(type)`,
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

// extendDevicesTypeCheck widens the devices.type CHECK constraint to include
// 'phone' and 'printer' (device types added after the original schema). SQLite
// cannot ALTER a CHECK in place, so on existing DBs the table is rebuilt with
// the new constraint; fresh installs already get the wider CHECK from
// schema.sql. The rebuild is shape-identical to the current table (only the
// CHECK clause differs) — same columns, same generated columns, same indexes
// (minus the legacy global-unique ip index that applyIdentityIndexMigrations
// recreates as the composite-unique (ip_address, network_id)).
//
// Idempotent: probes whether 'phone' is already accepted by the CHECK (sentinel
// INSERT + rollback); if so, the rebuild is a no-op. This mirrors the
// extendScanRunStatusCheck probe pattern.
func extendDevicesTypeCheck(ctx context.Context, db *sql.DB) error {
	// Probe: can the current CHECK accept 'phone'? Insert a sentinel row in a
	// rolled-back transaction; a CHECK violation means the migration is needed.
	probe, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin type-check probe tx: %w", err)
	}
	probeErr := func() error {
		if _, err := probe.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
			return err
		}
		_, err := probe.ExecContext(ctx,
			`INSERT INTO devices (name, type) VALUES ('__type_probe__', 'phone')`)
		return err
	}()
	_ = probe.Rollback()
	if probeErr == nil {
		// CHECK already permits 'phone' — nothing to do.
		return nil
	}
	if !strings.Contains(probeErr.Error(), "CHECK constraint failed") {
		return fmt.Errorf("probe devices type CHECK: %w", probeErr)
	}

	slog.Info("rebuilding devices table to widen type CHECK (add phone, printer)")

	// Rebuild preserving the FULL current column set — only the CHECK clause on
	// `type` differs (now includes 'phone', 'printer'). GENERATED ALWAYS AS
	// columns are derived on insert, not copied explicitly.
	stmts := []string{
		`CREATE TABLE devices_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL DEFAULT 'other' CHECK(type IN ('pc', 'embedded', 'iot', 'other', 'server', 'switch', 'router', 'firewall', 'nas', 'camera', 'phone', 'printer')),
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
			network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
			first_seen TIMESTAMP,
			last_seen TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO devices_new (id, name, type, brand, model, location, purpose, description,
			status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags,
			scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports,
			detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms,
			scan_attributes, user_attributes, network_id, first_seen, last_seen, created_at, updated_at)
		SELECT id, name, type, brand, model, location, purpose, description,
			status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags,
			scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports,
			detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms,
			scan_attributes, user_attributes, network_id, first_seen, last_seen, created_at, updated_at FROM devices`,
		`DROP TABLE devices`,
		`ALTER TABLE devices_new RENAME TO devices`,
		// Recreate the non-identity indexes (the composite-unique ip+network_id
		// index is recreated by applyIdentityIndexMigrations, which runs after).
		`CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status)`,
		`CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(type)`,
		`CREATE INDEX IF NOT EXISTS idx_devices_scan_mac_expr    ON devices(json_extract(scan_attributes, '$.mac'))`,
		`CREATE INDEX IF NOT EXISTS idx_devices_scan_vendor_expr ON devices(json_extract(scan_attributes, '$.vendor'))`,
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin type-check rebuild tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return fmt.Errorf("disable FKs for type-check rebuild: %w", err)
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("type-check rebuild step failed: %w (stmt: %s)", err, s)
		}
	}
	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("re-enable FKs after type-check rebuild: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit type-check rebuild: %w", err)
	}
	slog.Info("devices type CHECK widened (phone, printer added)")
	return nil
}

// extendUsersRoleCheck widens the users.role CHECK constraint to include
// 'operator' and 'viewer' (the RBAC capability graph, #138). SQLite cannot
// ALTER a CHECK in place, so on existing DBs the table is rebuilt with the new
// constraint; fresh installs already get the wider CHECK from schema.sql. The
// rebuild is shape-identical to the current table (only the CHECK clause on
// `role` differs) — same columns, same UNIQUE(username)/UNIQUE(email) implicit
// indexes (recreated by the column definitions), no explicit secondary indexes.
//
// Idempotent: probes whether 'operator' is already accepted by the CHECK
// (sentinel INSERT + rollback); if so, the rebuild is a no-op. This mirrors the
// extendDevicesTypeCheck probe pattern.
//
// Behavior is purely additive: existing 'admin'/'user' rows stay valid, and no
// route grants the new roles new access yet (that is the route-remap follow-up).
// This migration only enables an admin to CREATE operator/viewer users.
func extendUsersRoleCheck(ctx context.Context, db *sql.DB) error {
	// Probe: can the current CHECK accept 'operator'? Insert a sentinel row in a
	// rolled-back transaction; a CHECK violation means the migration is needed.
	probe, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin role-check probe tx: %w", err)
	}
	probeErr := func() error {
		if _, err := probe.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
			return err
		}
		_, err := probe.ExecContext(ctx,
			`INSERT INTO users (username, email, password_hash, role) VALUES ('__role_probe__', '__role_probe__@invalid', 'x', 'operator')`)
		return err
	}()
	_ = probe.Rollback()
	if probeErr == nil {
		// CHECK already permits 'operator' — nothing to do.
		return nil
	}
	if !strings.Contains(probeErr.Error(), "CHECK constraint failed") {
		return fmt.Errorf("probe users role CHECK: %w", probeErr)
	}

	slog.Info("rebuilding users table to widen role CHECK (add operator, viewer)")

	// Rebuild preserving the FULL current column set — only the CHECK clause on
	// `role` differs (now includes 'operator', 'viewer'). No generated columns,
	// no explicit secondary indexes to recreate (UNIQUE constraints come back via
	// the column definitions; FKs referencing users(id) survive via FKs=OFF).
	stmts := []string{
		`CREATE TABLE users_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'operator', 'viewer', 'user')),
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			failed_login_attempts INTEGER NOT NULL DEFAULT 0,
			locked_until TIMESTAMP,
			password_changed_at DATETIME,
			must_change_password BOOLEAN NOT NULL DEFAULT 0
		)`,
		`INSERT INTO users_new (id, username, email, password_hash, role, created_at, updated_at,
			failed_login_attempts, locked_until, password_changed_at, must_change_password)
		SELECT id, username, email, password_hash, role, created_at, updated_at,
			failed_login_attempts, locked_until, password_changed_at, must_change_password FROM users`,
		`DROP TABLE users`,
		`ALTER TABLE users_new RENAME TO users`,
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin role-check rebuild tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return fmt.Errorf("disable FKs for role-check rebuild: %w", err)
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("role-check rebuild step failed: %w (stmt: %s)", err, s)
		}
	}
	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("re-enable FKs after role-check rebuild: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit role-check rebuild: %w", err)
	}
	slog.Info("users role CHECK widened (operator, viewer added)")
	return nil
}

// backfillScanTaskNetworks resolves scan_tasks.network_id for existing tasks
// (#138 Phase 2c): each NULL-network task's targets go through the same
// ResolveNetworkFromTargets the create/update path uses — a single CIDR
// exactly matching a networks.cidr resolves to that network's id; anything
// else (multi-CIDR lists, IP ranges, hostnames, no match) stays NULL, which
// means cross-network/unresolved (admins see it, restricted scopes don't).
// Idempotent: resolvable rows are stamped once; the rest re-resolve cheaply
// on every startup (scan_tasks is a small table).
func backfillScanTaskNetworks(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT id, targets FROM scan_tasks WHERE network_id IS NULL`)
	if err != nil {
		return fmt.Errorf("select scan_tasks for network backfill: %w", err)
	}
	type pending struct {
		id      int64
		targets string
	}
	var batch []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.targets); err != nil {
			rows.Close()
			return fmt.Errorf("scan scan_tasks row for network backfill: %w", err)
		}
		batch = append(batch, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate scan_tasks for network backfill: %w", err)
	}

	stamped := 0
	for _, p := range batch {
		netID, err := taskservice.ResolveNetworkFromTargets(ctx, db, p.targets)
		if err != nil {
			// Best-effort by design: a failed lookup leaves the task NULL
			// (unscoped) rather than failing the whole migration.
			slog.Warn("scan-task network backfill: resolve failed", "task_id", p.id, "error", err)
			continue
		}
		if !netID.Valid {
			continue
		}
		if _, err := db.ExecContext(ctx,
			`UPDATE scan_tasks SET network_id = ? WHERE id = ?`, netID.Int64, p.id); err != nil {
			return fmt.Errorf("stamp scan_task %d network: %w", p.id, err)
		}
		stamped++
	}
	if stamped > 0 {
		slog.Info("scan_tasks network_id backfilled", "tasks", stamped)
	}
	return nil
}

// applyUniqueIndexMigrations de-duplicates rows then creates UNIQUE indexes on
// heartbeat_configs(device_id, method). Safe to re-run.
//
// NOTE: the old devices(ip_address) global-unique index was replaced by
// applyIdentityIndexMigrations (composite (ip_address, network_id) + MAC index)
// to support distributed multi-LAN deployments. This function now only owns the
// heartbeat_configs index.
func applyUniqueIndexMigrations(ctx context.Context, db *sql.DB) error {
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

// backfillDeviceUUIDs assigns a stable device_uuid to every devices row that
// lacks one, then creates the UUID unique index. This is the synthetic-identity
// foundation: a stable, IP-independent key the satellite tables will reference so
// they follow a device across DHCP roams (replacing the IP-keyed lookups that
// broke when a device's address changed). Runs at every startup; idempotent
// (only fills empty/NULL uuids; the index is IF NOT EXISTS).
//
// UUIDs are Go-generated (uuid.NewString, RFC 4122 hyphenated) for format
// consistency with new device creation. Device counts are modest (LAN tool,
// hundreds to low thousands), so a row loop is fine.
func backfillDeviceUUIDs(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT id FROM devices WHERE device_uuid IS NULL OR device_uuid = ''`)
	if err != nil {
		return fmt.Errorf("select devices without uuid: %w", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("scan device id: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate devices without uuid: %w", err)
	}
	for _, id := range ids {
		if _, err := db.ExecContext(ctx,
			`UPDATE devices SET device_uuid = ? WHERE id = ?`, uuid.NewString(), id); err != nil {
			return fmt.Errorf("set device_uuid for id %d: %w", id, err)
		}
	}
	if len(ids) > 0 {
		slog.Info("device_uuid backfill", "devices_assigned", len(ids))
	}
	// Unique index on device_uuid. Empty-string default rows are all backfilled
	// above, so no collision on ''. Idempotent.
	if _, err := db.ExecContext(ctx,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_uuid ON devices(device_uuid)`); err != nil {
		return fmt.Errorf("create idx_devices_uuid: %w", err)
	}
	return nil
}

// backfillSatelliteUUIDs populates device_uuid on the IP-keyed satellite tables
// via a one-shot IP-join to devices. Reliable at migration time (IPs are
// consistent — same scan wrote both). After this, the application code switches
// the satellite writes to device-keyed upserts (PR-B), retiring the IP-join.
// Each statement is best-effort: a failure (e.g. a table not yet having the
// column on a partial upgrade) is logged, not fatal, since these are additive.
func backfillSatelliteUUIDs(ctx context.Context, db *sql.DB) error {
	// The device JOIN mirrors ListLostSnapshots: (ip, network_id) with a NULL
	// network_id fallback. host_services/service_evidence/host_tls_certs don't
	// carry network_id, so they join on IP alone (a device's IP is unique within
	// its network; cross-network IP collisions are rare on a LAN tool).
	stmts := []string{
		`UPDATE scan_snapshots SET device_uuid = COALESCE((
			SELECT d.device_uuid FROM devices d
			WHERE d.ip_address = scan_snapshots.ip
			  AND (d.network_id = scan_snapshots.network_id OR d.network_id IS NULL)
			LIMIT 1), '') WHERE device_uuid = ''`,
		`UPDATE host_services SET device_uuid = COALESCE((
			SELECT d.device_uuid FROM devices d WHERE d.ip_address = host_services.ip LIMIT 1), '')
			WHERE device_uuid = ''`,
		`UPDATE service_evidence SET device_uuid = COALESCE((
			SELECT d.device_uuid FROM devices d WHERE d.ip_address = service_evidence.ip LIMIT 1), '')
			WHERE device_uuid = ''`,
		`UPDATE host_tls_certs SET device_uuid = COALESCE((
			SELECT d.device_uuid FROM devices d WHERE d.ip_address = host_tls_certs.ip LIMIT 1), '')
			WHERE device_uuid = ''`,
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			// Best-effort: a missing column on a partial upgrade is recoverable on
			// the next start once the ALTER has run. Log and continue.
			slog.Warn("satellite device_uuid backfill statement failed", "error", err)
		}
	}
	return nil
}

// backfillOfflineSince populates devices.offline_since for rows that are already
// 'offline' but have a NULL offline_since (the column was just added by the ALTER
// above, so every existing row starts NULL). The flip time is approximated from
// updated_at — the last write to the row, which for an offline device is the
// status='offline' write itself (the closest available proxy for when it went
// offline). Online/unknown rows keep NULL (they're not offline, so the silent-
// device retention sweep correctly skips them). Idempotent: only touches NULLs on
// offline rows, so a second run is a no-op.
func backfillOfflineSince(ctx context.Context, db *sql.DB) error {
	res, err := db.ExecContext(ctx,
		`UPDATE devices SET offline_since = updated_at
		 WHERE status = 'offline' AND offline_since IS NULL`)
	if err != nil {
		return fmt.Errorf("backfill offline devices: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		slog.Info("offline_since backfill", "offline_devices_approximated", n)
	}
	return nil
}

// mergeDuplicateMACDevices collapses rows that share the same non-empty MAC into
// a single canonical row, re-pointing child tables. This heals the device-split
// symptom (same MAC in multiple devices rows, created via the mac=” placeholder
// hole or an unguarded manual add). Idempotent: no-op when there are no dupes.
//
// Canonical selection: prefer an 'online' row (has the freshest data), else the
// lowest id (oldest, most-referenced). The canonical keeps its id + uuid; ghosts
// (the losing rows) are deleted after their children are re-pointed. Child tables
// in the main DB use ON DELETE CASCADE, so re-pointing then deleting is safe.
// Child tables in the separate heartbeat.db (heartbeat_results/device_liveness)
// can't be touched cross-DB here; their orphaned-by-deleted-ghost rows age out
// via retention (the ghost's device_id no longer exists; reads JOIN-skip them).
func mergeDuplicateMACDevices(ctx context.Context, db *sql.DB) error {
	// Find MACs with >1 row.
	rows, err := db.QueryContext(ctx,
		`SELECT mac_address, count(*) FROM devices WHERE mac_address != '' GROUP BY mac_address HAVING count(*) > 1`)
	if err != nil {
		return fmt.Errorf("find duplicate-MAC groups: %w", err)
	}
	var macs []string
	for rows.Next() {
		var mac string
		var n int64
		if err := rows.Scan(&mac, &n); err != nil {
			rows.Close()
			return fmt.Errorf("scan duplicate-MAC group: %w", err)
		}
		macs = append(macs, mac)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate duplicate-MAC groups: %w", err)
	}
	if len(macs) == 0 {
		return nil
	}

	// Child tables whose device_id must be re-pointed from each ghost to the
	// canonical. change_log.entity_id is polymorphic (no FK) but carries device
	// ids for device events — re-point it too so history follows the device.
	childDeviceIDCols := []struct{ table, col string }{
		{"heartbeat_configs", "device_id"},
		{"device_documents", "device_id"},
		{"device_systems", "device_id"},
		{"device_neighbors", "device_id"},
		{"device_neighbors", "neighbor_device_id"},
		{"topology_edges", "from_device_id"},
		{"topology_edges", "to_device_id"},
		{"change_log", "entity_id"},
	}

	var totalMerged int
	for _, mac := range macs {
		// Pick canonical: online first, then lowest id.
		var canonicalID int64
		if err := db.QueryRowContext(ctx,
			`SELECT id FROM devices WHERE mac_address = ? ORDER BY CASE status WHEN 'online' THEN 0 ELSE 1 END, id LIMIT 1`,
			mac).Scan(&canonicalID); err != nil {
			slog.Warn("merge dup-MAC: pick canonical failed", "mac", mac, "error", err)
			continue
		}
		// Ghosts = the other rows.
		gRows, err := db.QueryContext(ctx, `SELECT id FROM devices WHERE mac_address = ? AND id != ?`, mac, canonicalID)
		if err != nil {
			slog.Warn("merge dup-MAC: list ghosts failed", "mac", mac, "error", err)
			continue
		}
		var ghostIDs []int64
		for gRows.Next() {
			var gid int64
			if err := gRows.Scan(&gid); err == nil {
				ghostIDs = append(ghostIDs, gid)
			}
		}
		gRows.Close()

		for _, gid := range ghostIDs {
			// Re-point children from ghost → canonical.
			for _, c := range childDeviceIDCols {
				if _, err := db.ExecContext(ctx,
					`UPDATE `+c.table+` SET `+c.col+` = ? WHERE `+c.col+` = ?`, canonicalID, gid); err != nil {
					slog.Warn("merge dup-MAC: re-point child failed", "table", c.table, "col", c.col, "ghost", gid, "error", err)
				}
			}
			// Re-point satellite device_uuid rows (host_services/host_tls_certs/
			// service_evidence/scan_snapshots) that were IP-joined to the ghost's
			// IP — they should follow the canonical device_uuid instead. The ghost's
			// uuid is now orphaned; rows carrying it move to the canonical's uuid.
			var canonicalUUID string
			if err := db.QueryRowContext(ctx, `SELECT device_uuid FROM devices WHERE id = ?`, canonicalID).Scan(&canonicalUUID); err == nil && canonicalUUID != "" {
				var ghostUUID string
				if err := db.QueryRowContext(ctx, `SELECT device_uuid FROM devices WHERE id = ?`, gid).Scan(&ghostUUID); err == nil && ghostUUID != "" && ghostUUID != canonicalUUID {
					for _, t := range []string{"host_services", "service_evidence", "host_tls_certs", "scan_snapshots"} {
						if _, err := db.ExecContext(ctx, `UPDATE `+t+` SET device_uuid = ? WHERE device_uuid = ?`, canonicalUUID, ghostUUID); err != nil {
							slog.Warn("merge dup-MAC: re-point satellite uuid failed", "table", t, "error", err)
						}
					}
				}
			}
			// Delete the ghost (CASCADE cleans up any FK children not re-pointed).
			if _, err := db.ExecContext(ctx, `DELETE FROM devices WHERE id = ?`, gid); err != nil {
				slog.Warn("merge dup-MAC: delete ghost failed", "ghost", gid, "error", err)
			} else {
				totalMerged++
			}
		}
	}
	if totalMerged > 0 {
		slog.Info("duplicate-MAC merge", "ghosts_removed", totalMerged, "mac_groups", len(macs))
	}
	return nil
}

// applyIdentityIndexMigrations replaces the legacy global-unique
// devices(ip_address) index with the distributed-ready identity model:
//
//  1. DROP idx_devices_ip_address (the old global-unique IP index) so the same
//     private IP can coexist across two networks (e.g. both LANs have a .1).
//  2. De-duplicate by (ip_address, network_id) keeping the lowest id, then
//     CREATE UNIQUE INDEX idx_devices_ip_network ON (ip_address, network_id).
//     NULL network_id is allowed multiple times — SQLite treats each NULL as
//     distinct in a UNIQUE index, so legacy single-instance rows (network_id
//     still NULL) don't collide. When network_id is set it partitions by network.
//  3. CREATE INDEX idx_devices_mac_address ON (mac_address) to back the
//     MAC-primary device lookup (the scanner upserts by MAC when available so a
//     roaming/re-DHCP device stays one asset across networks).
//
// Safe to re-run: the DROP errors harmlessly when the index is already gone
// (legacy fresh installs never had it), and the CREATEs are IF NOT EXISTS.
func applyIdentityIndexMigrations(ctx context.Context, db *sql.DB) error {
	// 1. Drop the old global-unique IP index. Harmless no-op if it doesn't exist.
	if _, err := db.ExecContext(ctx, `DROP INDEX IF EXISTS idx_devices_ip_address`); err != nil {
		return fmt.Errorf("drop idx_devices_ip_address: %w", err)
	}

	// 2. De-duplicate by (ip_address, network_id), keeping the lowest id per
	//    pair. Only consider non-empty ip_address ('' = no IP, many rows legit).
	//    Rows with NULL network_id are grouped as a single partition (SQLite
	//    GROUP BY treats NULLs as equal). This prevents the composite-unique
	//    index creation from failing on legacy dupes.
	if _, err := db.ExecContext(ctx, `DELETE FROM devices WHERE id NOT IN (
		SELECT MIN(id) FROM devices
		WHERE ip_address != ''
		GROUP BY ip_address, network_id
	) AND ip_address != '' AND id IN (
		SELECT d.id FROM devices d
		JOIN (
			SELECT ip_address, network_id FROM devices
			WHERE ip_address != ''
			GROUP BY ip_address, network_id HAVING COUNT(*) > 1
		) dup ON d.ip_address = dup.ip_address
		       AND (d.network_id IS dup.network_id OR (d.network_id IS NULL AND dup.network_id IS NULL))
	)`); err != nil {
		// Non-fatal: log and continue; the index creation below surfaces a hard
		// failure if dupes actually remain.
		slog.Warn("devices (ip_address, network_id) de-dup sweep failed", "error", err)
	}
	if _, err := db.ExecContext(ctx,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip_network ON devices(ip_address, network_id)`); err != nil {
		return fmt.Errorf("create idx_devices_ip_network: %w", err)
	}

	// 3. MAC-primary lookup index. mac_address may be empty for many rows
	//    (legacy/manual devices), but a plain (non-unique) index is fine: the
	//    upsert filters `WHERE mac_address = ? AND mac_address != ''` so empty
	//    rows are never matched.
	if _, err := db.ExecContext(ctx,
		`CREATE INDEX IF NOT EXISTS idx_devices_mac_address ON devices(mac_address)`); err != nil {
		return fmt.Errorf("create idx_devices_mac_address: %w", err)
	}

	// networks.name unique — backs resolveNetworkID's ON CONFLICT(name) upsert.
	// Fresh installs get it from the UNIQUE constraint in schema.sql; this index
	// covers upgraded DBs that created the table before the constraint existed.
	if _, err := db.ExecContext(ctx,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_networks_name ON networks(name)`); err != nil {
		// Non-fatal: a dupe-name row would only arise if an operator manually
		// inserted one; log and let the upsert path surface it.
		slog.Warn("networks name unique index creation skipped", "error", err)
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

// extendNotificationChannelTypeCheck widens notification_channels' type CHECK
// to the chat-platform channel family (#284): feishu / wecom / telegram /
// discord join webhook + email. Existing installs carry the 2-value CHECK from
// the original CREATE TABLE, so a rebuild (create-new → copy → drop → rename)
// is required; schema.sql already ships the widened CHECK for fresh installs.
// Probe-first keeps it a no-op on rebuilt/new databases.
func extendNotificationChannelTypeCheck(ctx context.Context, db *sql.DB) error {
	probe, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin probe tx: %w", err)
	}
	probeErr := func() error {
		_, err := probe.ExecContext(ctx,
			`INSERT INTO notification_channels (name, type) VALUES ('_probe', 'feishu')`)
		return err
	}()
	_ = probe.Rollback()
	if probeErr == nil {
		return nil // CHECK already permits the new types
	}
	if !strings.Contains(probeErr.Error(), "CHECK constraint failed") {
		return fmt.Errorf("probe notification_channels CHECK: %w", probeErr)
	}

	slog.Info("rebuilding notification_channels to widen the type CHECK (feishu/wecom/telegram/discord)")
	stmts := []string{
		`CREATE TABLE notification_channels_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL CHECK(type IN ('webhook', 'email', 'feishu', 'wecom', 'telegram', 'discord')),
			config TEXT NOT NULL DEFAULT '{}',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO notification_channels_new (id, name, type, config, enabled, created_at, updated_at)
		 SELECT id, name, type, config, enabled, created_at, updated_at FROM notification_channels`,
		`DROP TABLE notification_channels`,
		`ALTER TABLE notification_channels_new RENAME TO notification_channels`,
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin rebuild tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, st := range stmts {
		if _, err := tx.ExecContext(ctx, st); err != nil {
			return fmt.Errorf("rebuild step failed: %w (stmt: %s)", err, st)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit rebuild: %w", err)
	}
	slog.Info("notification_channels rebuilt with the widened type CHECK")
	return nil
}

// pruneOldBackups deletes files in dir whose names start with prefix and whose
// modification time is older than maxAge. Best-effort: failures are logged and
// never abort startup. Used for the VACUUM INTO pre-migration backups that
// otherwise accumulate unboundedly (#257).
func pruneOldBackups(dir, prefix string, maxAge time.Duration) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
			slog.Info("pruned old pre-migration backup", "file", e.Name())
		}
	}
}

// convertDashboardConfigPosition rebuilds dashboard_configs with an INTEGER
// position column (#247). The first release stored TEXT ('{}' default): the
// frontend sorted numerically (NaN against '{}' strings) and the create path
// never sent a value, so no widget could ever render in a custom layout.
// Legacy rows are assigned 1-based display order by id — deterministic and
// stable for however many stragglers an upgraded DB carries.
//
// Idempotent: probes the declared column type via PRAGMA table_info; the
// rebuild is a no-op once position is INTEGER. Mirrors the rebuild pattern of
// extendUsersRoleCheck (FKs off inside the tx, full column set preserved).
func convertDashboardConfigPosition(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(dashboard_configs)`)
	if err != nil {
		return fmt.Errorf("probe dashboard_configs shape: %w", err)
	}
	isText := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltValue any
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("scan table_info row: %w", err)
		}
		if name == "position" {
			isText = strings.Contains(strings.ToUpper(colType), "TEXT")
			break
		}
	}
	// Close the cursor BEFORE the rebuild: an open read cursor on another pool
	// connection blocks the rebuild tx's commit on non-WAL databases (SQLITE_BUSY).
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fmt.Errorf("iterate table_info: %w", err)
	}
	if !isText {
		return nil
	}

	slog.Info("rebuilding dashboard_configs table (position TEXT -> INTEGER, #247)")

	stmts := []string{
		`CREATE TABLE dashboard_configs_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			type TEXT NOT NULL CHECK(type IN ('gauge', 'line', 'bar', 'pie')),
			data_source TEXT NOT NULL DEFAULT 'prometheus' CHECK(data_source IN ('prometheus', 'victoriametrics')),
			query TEXT NOT NULL DEFAULT '',
			refresh_interval INTEGER NOT NULL DEFAULT 30,
			position INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO dashboard_configs_new (id, name, type, data_source, query, refresh_interval, position, created_at, updated_at)
		SELECT id, name, type, data_source, query, refresh_interval,
			CAST(ROW_NUMBER() OVER (ORDER BY id) AS INTEGER), created_at, updated_at
		FROM dashboard_configs`,
		`DROP TABLE dashboard_configs`,
		`ALTER TABLE dashboard_configs_new RENAME TO dashboard_configs`,
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin dashboard-configs rebuild tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return fmt.Errorf("disable FKs for dashboard-configs rebuild: %w", err)
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("dashboard-configs rebuild step failed: %w (stmt: %s)", err, s)
		}
	}
	if _, err := tx.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("re-enable FKs after dashboard-configs rebuild: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit dashboard-configs rebuild: %w", err)
	}
	slog.Info("dashboard_configs position converted to INTEGER (legacy rows ordered by id)")
	return nil
}
