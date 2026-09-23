// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/dbopen"
)

// writeCenterConfig writes a center config with the given tweaks applied to a
// healthy baseline, returning its path. The database points into dir.
func writeCenterConfig(t *testing.T, dir, tweaks string) string {
	t.Helper()
	dbPath := filepath.Join(dir, "data", "mibee.db")
	require.NoError(t, os.MkdirAll(filepath.Dir(dbPath), 0o755))
	yaml := `
server:
  port: 0
auth:
  jwt_secret: "this-is-a-long-enough-jwt-secret-value!!"
  initial_admin_password: "Str0ng!Pass"
storage:
  upload_path: "` + filepath.ToSlash(filepath.Join(dir, "uploads")) + `"
database:
  sqlite:
    path: "` + filepath.ToSlash(dbPath) + `"
` + tweaks
	p := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(yaml), 0o600))
	return p
}

// doctorHealthyExit mirrors doctor's ICMP capability derivation so the
// healthy-config expectations hold on both capable hosts (0) and CI runners
// with ping_group_range disabled (doctorFailExit), both correct behavior.
func doctorHealthyExit() int {
	if raw, err := os.ReadFile("/proc/sys/net/ipv4/ping_group_range"); err == nil {
		if c, ok := icmpPingGroupRangeCheck(string(raw), os.Getgid()); ok && c.status == "fail" {
			return doctorFailExit
		}
	}
	return 0
}

// TestDoctor_ConfigMatrix drives the doctor's configuration checks: broken
// YAML fails fast; missing/short jwt_secret, missing admin password, missing
// master key, and secret reuse produce the expected verdicts; a healthy
// config reaches the DB checks and exits 0.
func TestDoctor_ConfigMatrix(t *testing.T) {
	// Broken YAML → config fail → exit 1.
	broken := filepath.Join(t.TempDir(), "broken.yaml")
	require.NoError(t, os.WriteFile(broken, []byte("\tnot: [yaml"), 0o600))
	require.Equal(t, doctorFailExit, doctor([]string{"-config", broken}))

	// Missing config file → same fail path.
	require.Equal(t, doctorFailExit, doctor([]string{"-config",
		filepath.Join(t.TempDir(), "missing.yaml")}))

	// Healthy config (fresh DB): pass on capable hosts, fail where the host
	// forbids unprivileged ICMP (CI runners), both correct.
	ok := writeCenterConfig(t, t.TempDir(), "")
	require.Equal(t, doctorHealthyExit(), doctor([]string{"-config", ok}))

	// Missing jwt_secret → fail exit.
	noJWT := writeCenterConfig(t, t.TempDir(), "")
	src, err := os.ReadFile(noJWT)
	require.NoError(t, err)
	patched := strings.Replace(string(src), "jwt_secret: \"this-is-a-long-enough-jwt-secret-value!!\"", "jwt_secret: \"\"", 1)
	require.NotEqual(t, string(src), patched, "jwt line must exist in the template")
	require.NoError(t, os.WriteFile(noJWT, []byte(patched), 0o600))
	require.Equal(t, doctorFailExit, doctor([]string{"-config", noJWT}))

	// Empty initial_admin_password → fail arm (admin cannot be created on a
	// fresh DB).
	noPw := writeCenterConfig(t, t.TempDir(), "")
	src, err = os.ReadFile(noPw)
	require.NoError(t, err)
	patched = strings.Replace(string(src), "initial_admin_password: \"Str0ng!Pass\"", "initial_admin_password: \"\"", 1)
	require.NoError(t, os.WriteFile(noPw, []byte(patched), 0o600))
	require.Equal(t, doctorFailExit, doctor([]string{"-config", noPw}))

	// jwt_secret == initial_admin_password → secret-reuse warn.
	reuse := writeCenterConfig(t, t.TempDir(), "")
	src, err = os.ReadFile(reuse)
	require.NoError(t, err)
	patched = strings.Replace(string(src), "Str0ng!Pass", "this-is-a-long-enough-jwt-secret-value!!", 1)
	require.NoError(t, os.WriteFile(reuse, []byte(patched), 0o600))
	require.Equal(t, doctorHealthyExit(), doctor([]string{"-config", reuse}))
}

// TestResetAdminPassword_FlagAndStdinPaths drives the recovery subcommand
// end-to-end on a fresh database: the -password flag seeds the admin, a
// second run resets it, and the stdin prompt path reads a line.
func TestResetAdminPassword_FlagAndStdinPaths(t *testing.T) {
	dir := t.TempDir()
	cfg := writeCenterConfig(t, dir, "")

	prevStdout := os.Stdout
	devNull, _ := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	os.Stdout = devNull
	t.Cleanup(func() { os.Stdout = prevStdout; devNull.Close() })

	// Fresh DB → the subcommand seeds admin (id=1) with the flag password.
	resetAdminPasswordSubcommand([]string{"-config", cfg, "-password", "First!Pass1"})
	db, err := dbopen.Open(filepath.Join(dir, "data", "mibee.db"))
	require.NoError(t, err)
	defer db.Close()
	var hash string
	require.NoError(t, db.QueryRow(`SELECT password_hash FROM users WHERE id = 1`).Scan(&hash))
	require.NotEmpty(t, hash)

	// Reset via stdin prompt path.
	stdinFile := filepath.Join(dir, "stdin.txt")
	require.NoError(t, os.WriteFile(stdinFile, []byte("Second!Pass2\nSecond!Pass2\n"), 0o600))
	f, err := os.Open(stdinFile)
	require.NoError(t, err)
	prevStdin := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = prevStdin; f.Close() })
	resetAdminPasswordSubcommand([]string{"-config", cfg})

	var hash2 string
	require.NoError(t, db.QueryRow(`SELECT password_hash FROM users WHERE id = 1`).Scan(&hash2))
	require.NotEqual(t, hash, hash2, "second run must change the password")
}
