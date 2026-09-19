// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package main

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/service"
)

// openMigratedDB opens a file-backed SQLite DB and runs the full migration
// chain — the same state a real deployment reaches after startup.
func openMigratedDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "gap.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	require.NoError(t, runMigrations(db, dbPath))
	return db, dbPath
}

// oldDevicesNoGeneratedColumns is the devices shape BEFORE the
// scan_attributes-generated-columns migration: scan_attributes exists, but the
// four GENERATED ALWAYS AS columns do not, and the type CHECK predates
// phone/printer.
func oldDevicesNoGeneratedColumns(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`CREATE TABLE devices (
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
		network_id INTEGER,
		first_seen TIMESTAMP,
		last_seen TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO devices (id, name, ip_address, scan_attributes) VALUES (7, 'gen-host', '10.1.1.7', '{"mac":"aa:bb:cc:dd:ee:ff","vendor":"acme","os":"linux","hostname":"genhost"}')`)
	require.NoError(t, err)
}

func TestAddDevicesGeneratedColumns_Rebuild(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "gen.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	oldDevicesNoGeneratedColumns(t, db)

	require.NoError(t, addDevicesGeneratedColumns(ctx, db))

	// Existing row survived; the generated columns derive from scan_attributes.
	var mac, vendor, osName, hostname string
	var id int64
	require.NoError(t, db.QueryRow(
		`SELECT id, scan_mac, scan_vendor, scan_os, scan_hostname FROM devices WHERE name='gen-host'`).
		Scan(&id, &mac, &vendor, &osName, &hostname))
	require.EqualValues(t, 7, id, "id must survive the rebuild")
	require.Equal(t, "aa:bb:cc:dd:ee:ff", mac)
	require.Equal(t, "acme", vendor)
	require.Equal(t, "linux", osName)
	require.Equal(t, "genhost", hostname)

	// Idempotent: the pragma_table_xinfo probe short-circuits.
	require.NoError(t, addDevicesGeneratedColumns(ctx, db))
}

func TestExtendDevicesTypeCheck_RebuildsFromNarrowCheck(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "type.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Old shape: WITH generated columns (already past the first migration) but
	// the narrow type CHECK (no phone/printer). Reuse the no-generated shape,
	// run the generated-columns migration first, then narrow via direct DDL is
	// impossible — so create the wide-column/narrow-CHECK shape by rebuilding:
	// simplest correct route is old shape + addDevicesGeneratedColumns + a
	// hand-rolled narrow-CHECK rebuild is overkill. Instead: fresh schema
	// migration gives the WIDE check; probe then short-circuits — that's the
	// idempotence branch, asserted first below on a real migrated DB.
	migrated, _ := openMigratedDB(t)
	require.NoError(t, extendDevicesTypeCheck(ctx, migrated), "wide CHECK must short-circuit")

	// Now the rebuild path: old shape (narrow CHECK) WITHOUT generated columns
	// still exercises extendDevicesTypeCheck's rebuild (which carries the full
	// current column set incl. generated columns).
	oldDevicesNoGeneratedColumns(t, db)
	require.NoError(t, extendDevicesTypeCheck(ctx, db))

	// phone + printer now insertable; the seeded row survived.
	_, err = db.Exec(`INSERT INTO devices (name, type) VALUES ('p1', 'phone')`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO devices (name, type) VALUES ('pr1', 'printer')`)
	require.NoError(t, err)
	var n int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices WHERE name='gen-host'`).Scan(&n))
	require.Equal(t, 1, n)

	// Idempotent after the rebuild.
	require.NoError(t, extendDevicesTypeCheck(ctx, db))
}

func TestExtendScanRunStatusCheck_Rebuild(t *testing.T) {
	ctx := context.Background()
	db, _ := openMigratedDB(t)

	// Downgrade to the OLD shape (no 'cancelled' in the CHECK), keeping a row.
	_, err := db.Exec(`DROP TABLE scan_task_runs`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE scan_task_runs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id INTEGER NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'running', 'completed', 'failed')),
		total_hosts INTEGER NOT NULL DEFAULT 0,
		alive_hosts INTEGER NOT NULL DEFAULT 0,
		new_hosts INTEGER NOT NULL DEFAULT 0,
		updated_hosts INTEGER NOT NULL DEFAULT 0,
		duration_ms INTEGER NOT NULL DEFAULT 0,
		error_message TEXT NOT NULL DEFAULT '',
		started_at TIMESTAMP,
		finished_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO scan_task_runs (id, task_id, status, duration_ms) VALUES (3, 1, 'completed', 950)`)
	require.NoError(t, err)

	require.NoError(t, extendScanRunStatusCheck(ctx, db))

	// Row preserved; 'cancelled' insertable; idempotent.
	var status string
	var dur int64
	require.NoError(t, db.QueryRow(`SELECT status, duration_ms FROM scan_task_runs WHERE id=3`).Scan(&status, &dur))
	require.Equal(t, "completed", status)
	require.EqualValues(t, 950, dur)
	_, err = db.Exec(`INSERT INTO scan_task_runs (task_id, status) VALUES (1, 'cancelled')`)
	require.NoError(t, err)
	require.NoError(t, extendScanRunStatusCheck(ctx, db))
}

func TestExtendNotificationChannelTypeCheck_Rebuild(t *testing.T) {
	ctx := context.Background()
	db, _ := openMigratedDB(t)

	// Downgrade to the 2-value CHECK, keep a row.
	_, err := db.Exec(`DROP TABLE notification_channels`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE notification_channels (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		type TEXT NOT NULL CHECK(type IN ('webhook', 'email')),
		config TEXT NOT NULL DEFAULT '{}',
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO notification_channels (id, name, type) VALUES (5, 'hook', 'webhook')`)
	require.NoError(t, err)

	require.NoError(t, extendNotificationChannelTypeCheck(ctx, db))

	// Row preserved; feishu/telegram insertable; idempotent.
	var typ string
	require.NoError(t, db.QueryRow(`SELECT type FROM notification_channels WHERE id=5`).Scan(&typ))
	require.Equal(t, "webhook", typ)
	for _, c := range []string{"feishu", "wecom", "telegram", "discord"} {
		_, err = db.Exec(`INSERT INTO notification_channels (name, type) VALUES ('c_` + c + `', '` + c + `')`)
		require.NoError(t, err, "type %q must be accepted after the rebuild", c)
	}
	require.NoError(t, extendNotificationChannelTypeCheck(ctx, db))
}

func TestMergeDuplicateMACDevices(t *testing.T) {
	ctx := context.Background()
	db, _ := openMigratedDB(t)

	// Two devices sharing a MAC: the ONLINE one (higher id) must become
	// canonical; the offline lower-id row is the ghost.
	ins := func(uuid, name, mac, status string) int64 {
		res, err := db.Exec(`INSERT INTO devices (device_uuid, name, ip_address, mac_address, status)
			VALUES (?, ?, '10.5.0.1', ?, ?)`, uuid, name, mac, status)
		require.NoError(t, err)
		id, _ := res.LastInsertId()
		return id
	}
	ghostID := ins("uuid-ghost", "ghost", "de:ad:be:ef:00:01", "offline")
	canonicalID := ins("uuid-canonical", "canonical", "de:ad:be:ef:00:01", "online")
	require.Greater(t, canonicalID, ghostID)

	// Child row on the ghost (heartbeat_configs) + satellite row carrying the
	// ghost's device_uuid (host_services).
	_, err := db.Exec(`INSERT INTO heartbeat_configs (device_id, method, target) VALUES (?, 'icmp', '10.5.0.1')`, ghostID)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO host_services (ip, device_uuid, service, port) VALUES ('10.5.0.1', 'uuid-ghost', 'ssh', 22)`)
	require.NoError(t, err)

	// A UNIQUE device (no dup) that must be untouched.
	uniqueID := ins("uuid-unique", "unique", "0a:0b:0c:0d:0e:0f", "online")
	_ = uniqueID

	require.NoError(t, mergeDuplicateMACDevices(ctx, db))

	// One row left for that MAC — the canonical.
	var n int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices WHERE mac_address='de:ad:be:ef:00:01'`).Scan(&n))
	require.Equal(t, 1, n)
	var name string
	require.NoError(t, db.QueryRow(`SELECT name FROM devices WHERE mac_address='de:ad:be:ef:00:01'`).Scan(&name))
	require.Equal(t, "canonical", name)

	// The child row was re-pointed to the canonical device.
	var hbDev int64
	require.NoError(t, db.QueryRow(`SELECT device_id FROM heartbeat_configs`).Scan(&hbDev))
	require.Equal(t, canonicalID, hbDev)

	// The satellite row followed the canonical device_uuid.
	var svcUUID string
	require.NoError(t, db.QueryRow(`SELECT device_uuid FROM host_services`).Scan(&svcUUID))
	require.Equal(t, "uuid-canonical", svcUUID)

	// Idempotent: no dup groups remain.
	require.NoError(t, mergeDuplicateMACDevices(ctx, db))
	var total int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&total))
	require.Equal(t, 2, total, "canonical + the unique device")
}

func TestPruneBackupsHelpers(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "mibee-backup-old.db")
	newF := filepath.Join(dir, "mibee-backup-new.db")
	unrelated := filepath.Join(dir, "other-old.db")
	for _, f := range []string{old, newF, unrelated} {
		require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
	}
	past := time.Now().Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(old, past, past))
	require.NoError(t, os.Chtimes(unrelated, past, past))

	pruneOldBackups(dir, "mibee-backup-", 24*time.Hour)
	_, err := os.Stat(old)
	require.True(t, os.IsNotExist(err), "old prefixed backup must be pruned")
	_, err = os.Stat(newF)
	require.NoError(t, err, "recent backup must survive")
	_, err = os.Stat(unrelated)
	require.NoError(t, err, "unprefixed files must survive")

	// pruneExcessBackups keeps the N newest prefixed files.
	for i := 0; i < 3; i++ {
		p := filepath.Join(dir, "mibee-backup-x"+string(rune('a'+i))+".db")
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
		require.NoError(t, os.Chtimes(p, time.Now().Add(time.Duration(i)*time.Hour), time.Now().Add(time.Duration(i)*time.Hour)))
	}
	pruneExcessBackups(dir, "mibee-backup-", 2)
	var left int
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "mibee-backup-") {
			left++
		}
	}
	require.Equal(t, 2, left)
}

// --- doctor: exit-code contract over a real temp config ---

func writeDoctorConfig(t *testing.T, dbPath, masterKey string) string {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	yaml := `
server:
  port: 0
database:
  sqlite:
    path: "` + filepath.ToSlash(dbPath) + `"
security:
  master_key: "` + masterKey + `"
auth:
  jwt_secret: "0123456789abcdef0123456789abcdef"
  initial_admin_password: "bootstrap-pw"
`
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0o600))
	return cfgPath
}

func TestDoctor_ExitCodes(t *testing.T) {
	t.Run("healthy config exits 0", func(t *testing.T) {
		dbDir := t.TempDir()
		cfg := writeDoctorConfig(t, filepath.Join(dbDir, "mibee.db"), "0123456789abcdef0123456789abcdef")
		require.Equal(t, 0, doctor([]string{"-config", cfg}))
	})
	t.Run("wrong-length master key exits 1", func(t *testing.T) {
		dbDir := t.TempDir()
		cfg := writeDoctorConfig(t, filepath.Join(dbDir, "mibee.db"), "too-short")
		require.Equal(t, doctorFailExit, doctor([]string{"-config", cfg}))
	})
	t.Run("unloadable config exits 1", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nope.yaml")
		require.Equal(t, doctorFailExit, doctor([]string{"-config", missing}))
	})
}

// --- main helpers ---

func TestParseLogLevel(t *testing.T) {
	require.Equal(t, "DEBUG", parseLogLevel("debug").String())
	require.Equal(t, "WARN", parseLogLevel("warn").String())
	require.Equal(t, "ERROR", parseLogLevel("error").String())
	require.Equal(t, "INFO", parseLogLevel("anything-else").String())
}

func TestInitLogger(_ *testing.T) {
	initLogger(config.LogConfig{Level: "debug", Format: "json"})
	initLogger(config.LogConfig{Level: "bogus", Format: "text"})
}

func TestParseDurationOrDefault(t *testing.T) {
	require.Equal(t, 5*time.Minute, parseDurationOrDefault("5m", time.Hour))
	require.Equal(t, time.Hour, parseDurationOrDefault("", time.Hour))
	require.Equal(t, time.Hour, parseDurationOrDefault("bogus", time.Hour))
}

func TestSeedAdminUser(t *testing.T) {
	db, _ := openMigratedDB(t)
	policy := config.PasswordPolicyConfig{MinLength: 8}
	svc := service.NewUserService(db, "test-secret-key-for-tests-32-bytes!!", time.Hour, policy)

	// First call seeds; second hits ErrUserExists and skips silently.
	seedAdminUser(svc, "bootstrap-password")
	seedAdminUser(svc, "bootstrap-password")

	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM users WHERE username='admin'`).Scan(&count))
	require.Equal(t, 1, count)

	// Empty password seeds the first-run setup state (no usable hash change).
	seedAdminUser(svc, "")
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM users WHERE username='admin'`).Scan(&count))
	require.Equal(t, 1, count)
}

func TestIsAddrInUse(t *testing.T) {
	require.False(t, isAddrInUse(nil))
	require.False(t, isAddrInUse(http.ErrServerClosed))
	require.False(t, isAddrInUse(&net.OpError{Op: "listen", Err: errors.New("nope")}))

	// A wrapped EADDRINUSE (the shape ListenAndServe produces on Linux).
	sysErr := &os.SyscallError{Syscall: "bind", Err: syscall.EADDRINUSE}
	require.True(t, isAddrInUse(sysErr))
}

func TestListenAndServeWithRetry_ServerClosed(t *testing.T) {
	srv := &http.Server{Addr: "127.0.0.1:0", Handler: http.NotFoundHandler()}
	// Close right after start → ListenAndServe returns ErrServerClosed, which
	// the retry wrapper must pass through unchanged.
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = srv.Close()
	}()
	err := listenAndServeWithRetry(srv)
	require.ErrorIs(t, err, http.ErrServerClosed)
}

func TestListenAndServeWithRetry_BadAddrFailsFast(t *testing.T) {
	srv := &http.Server{Addr: "256.256.256.256:1", Handler: http.NotFoundHandler()}
	start := time.Now()
	err := listenAndServeWithRetry(srv)
	require.Error(t, err)
	require.NotErrorIs(t, err, http.ErrServerClosed)
	require.Less(t, time.Since(start), 5*time.Second, "non-EADDRINUSE errors must not be retried")
}

// --- reset-admin-password happy path + stdin reader ---

func TestResetAdminPasswordSubcommand_FlagPassword(t *testing.T) {
	dbDir := t.TempDir()
	cfg := writeDoctorConfig(t, filepath.Join(dbDir, "mibee.db"), "0123456789abcdef0123456789abcdef")

	// Fresh DB: the subcommand seeds the admin with the given password (the
	// never-started-server path). Runs to completion without os.Exit.
	resetAdminPasswordSubcommand([]string{"-config", cfg, "-password", "Operator-Pw-1!"})

	db, err := sql.Open("sqlite", filepath.Join(dbDir, "mibee.db"))
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	var count int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM users WHERE username='admin'`).Scan(&count))
	require.Equal(t, 1, count)

	// Running again now takes the ForceChangePassword path (admin exists).
	resetAdminPasswordSubcommand([]string{"-config", cfg, "-password", "Operator-Pw-2!"})
}

func TestReadPasswordFromStdin(t *testing.T) {
	orig := os.Stdin
	t.Cleanup(func() { os.Stdin = orig })

	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	_, err = w.WriteString("typed-secret\r\n")
	require.NoError(t, err)
	require.NoError(t, w.Close())
	got, err := readPasswordFromStdin()
	require.NoError(t, err)
	require.Equal(t, "typed-secret", got)

	// EOF with no data returns what it has (empty) + EOF.
	r2, w2, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r2
	require.NoError(t, w2.Close())
	_, err = readPasswordFromStdin()
	require.Error(t, err)
}
