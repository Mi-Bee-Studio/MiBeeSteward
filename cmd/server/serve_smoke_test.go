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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/dbopen"
	"mibee-steward/internal/service"
	"mibee-steward/internal/testutil"
)

// quietLogs swaps the default logger for a discard handler for the duration
// of a lifecycle test (the server logs heavily during startup/shutdown).
func quietLogs(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// TestServe_FullLifecycleInProcess boots the REAL server lifecycle in-process
// (serve → migrations → admin seed → NewRouter → HTTP listen), polls the
// public /health endpoint until it answers, then closes the stop channel and
// asserts a clean graceful shutdown, the exact sequence main() drives in
// production, minus signals. This is the deployment-shape smoke test: wiring
// bugs (a router constructor change, a migration crash, a seed regression)
// show up here even when every unit test still passes.
func TestServe_FullLifecycleInProcess(t *testing.T) {
	quietLogs(t)

	tmp := t.TempDir()

	// Ephemeral port: reserve, read the number, release, reuse. The tiny
	// TOCTOU window is fine for a test port on loopback.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())

	dbPath := filepath.Join(tmp, "data", "mibee.db")
	cfgYAML := fmt.Sprintf(`
server:
  host: "127.0.0.1"
  port: %d
  # Deliberately too low for scanner.default_timeout below — the auto-raise
  # guard branch must fire (write_timeout < default_timeout×2+30s).
  write_timeout: "10s"
database:
  sqlite:
    path: %q
storage:
  upload_path: %q
auth:
  jwt_secret: "smoke-test-secret-key-that-is-at-least-32-chars"
  initial_admin_password: ""
network:
  name: "smoke-test"
scanner:
  default_timeout: 5
`, port, dbPath, filepath.Join(tmp, "uploads"))
	cfgPath := filepath.Join(tmp, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgYAML), 0o600))

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)

	// main() creates the data directory before opening; mirror it here.
	require.NoError(t, os.MkdirAll(filepath.Dir(dbPath), 0o755))
	db, err := dbopen.Open(dbPath,
		"journal_mode=WAL",
		"busy_timeout=5000",
		"synchronous=NORMAL",
		"cache_size=-64000",
		"temp_store=MEMORY",
	)
	require.NoError(t, err)

	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- serve(cfg, db, dbPath, stop) }()

	// Poll /health (public, no auth) until the full wiring answers.
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	healthy := false
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/api/v1/health")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var payload struct {
					Status  string `json:"status"`
					Version string `json:"version"`
				}
				require.NoError(t, json.Unmarshal(body, &payload), "health payload: %s", body)
				require.Equal(t, "ok", payload.Status)
				healthy = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.True(t, healthy, "server never became healthy on port %d", port)

	// The first-run setup surface must also answer (public): an empty
	// initial_admin_password seeds the browser-guided setup flow.
	resp, err := http.Get(base + "/api/v1/auth/setup-status")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "setup-status: %s", body)
	var setup struct {
		Required bool `json:"required"`
	}
	require.NoError(t, json.Unmarshal(body, &setup))
	require.True(t, setup.Required, "empty initial_admin_password must leave first-run setup pending: %s", body)

	// Graceful shutdown: close(stop) must run the full sequence (heartbeat →
	// scanner → HTTP shutdown → db close) and return nil.
	close(stop)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(25 * time.Second):
		t.Fatal("serve did not return after stop was closed")
	}
}

// TestServeHTTP_BindFailureReturnsError pins the serveHTTP error contract: a
// port that cannot be bound (someone else holds it) shows up as a returned
// error, NOT an os.Exit from a goroutine, so the process lifecycle stays
// under main's control. The retry window is shrunk via the test seam so the
// EADDRINUSE loop (where the platform maps the errno as expected) terminates
// in milliseconds instead of 30s.
func TestServeHTTP_BindFailureReturnsError(t *testing.T) {
	quietLogs(t)

	// Hold the port for the whole test.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	port := l.Addr().(*net.TCPAddr).Port

	prevWindow, prevInterval := bindRetryWindow, bindRetryInterval
	bindRetryWindow, bindRetryInterval = 300*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { bindRetryWindow, bindRetryInterval = prevWindow, prevInterval })

	cfg := &config.Config{}
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.Port = port

	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	stop := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-stop:
		default:
			close(stop)
		}
	})

	done := make(chan error, 1)
	go func() { done <- serveHTTP(cfg, conn, stop) }()

	select {
	case err := <-done:
		require.Error(t, err, "bind failure must surface as an error")
	case <-time.After(20 * time.Second):
		t.Fatal("serveHTTP did not return on bind failure")
	}
}

// TestSeedAdminUser_Branches covers the seeding outcomes the smoke lifecycle
// can't repeat: the already-exists continuation and the temp-credential seed.
func TestSeedAdminUser_Branches(t *testing.T) {
	quietLogs(t)

	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	newSvc := func() *service.UserService {
		return service.NewUserService(conn, "test-secret-key-for-tests-32-bytes!!", time.Hour, config.PasswordPolicyConfig{})
	}

	// Empty password → first-run state (no usable credential yet).
	seedAdminUser(newSvc(), "")
	// Second call with any password → already exists, skips silently.
	seedAdminUser(newSvc(), "Temp-Password-1")
	// The account exists and still has the password-less state.
	var hash string
	require.NoError(t, conn.QueryRow(`SELECT password_hash FROM users WHERE username='admin'`).Scan(&hash))
	require.Empty(t, hash, "the second seed must not overwrite the empty password")

	// A separate fresh DB with a non-empty password → temp credential.
	conn2, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn2.Close() })
	svc2 := service.NewUserService(conn2, "test-secret-key-for-tests-32-bytes!!", time.Hour, config.PasswordPolicyConfig{})
	seedAdminUser(svc2, "Temp-Password-1")
	var hash2 string
	require.NoError(t, conn2.QueryRow(`SELECT password_hash FROM users WHERE username='admin'`).Scan(&hash2))
	require.NotEmpty(t, hash2, "non-empty seed must store a real password hash")
}
