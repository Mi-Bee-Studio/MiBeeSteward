// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. A commercial license is available for use cases
// the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package main

import (
	"database/sql"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/service"
)

// openMigratedDB opens a file-backed SQLite DB and bootstraps it the same way
// startup does.
func openMigratedDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "gap.db")
	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	require.NoError(t, runMigrations(db, dbPath))
	return db, dbPath
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
	t.Run("healthy config exits cleanly", func(t *testing.T) {
		dbDir := t.TempDir()
		cfg := writeDoctorConfig(t, filepath.Join(dbDir, "mibee.db"), "0123456789abcdef0123456789abcdef")
		// The ICMP capability check reads the host's ping_group_range sysctl
		// (absent on Windows, present on Linux runners where it may be
		// disabled "1 0"). Mirror doctor's own logic to derive the expected
		// exit: 0 on capable hosts, doctorFailExit where ICMP is disabled;
		// both are correct behavior for this config.
		wantExit := 0
		if raw, err := os.ReadFile("/proc/sys/net/ipv4/ping_group_range"); err == nil {
			if c, ok := icmpPingGroupRangeCheck(string(raw), os.Getgid()); ok && c.status == "fail" {
				wantExit = doctorFailExit
			}
		}
		require.Equal(t, wantExit, doctor([]string{"-config", cfg}))
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
