// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package routes

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"mibee-steward/internal/config"
)

func jsonReader(s string) *strings.Reader { return strings.NewReader(s) }

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// demoCfg is the parity-test config plus demo mode, a parseable token expiry
// (exercising the duration branch), and unlimited rate limits.
func demoCfg() *config.Config {
	cfg := newTestConfig()
	cfg.Server.DemoMode = true
	cfg.Auth.TokenExpiry = "1h"
	return cfg
}

// loginAdmin inserts a known-password admin and logs in through the live
// router, returning the bearer token.
func loginAdmin(t *testing.T, conn *sql.DB, router http.Handler) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("Str0ng!Pass"), bcrypt.MinCost)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO users (username, email, password_hash, role)
		VALUES ('demo-admin', 'demo-admin@test.com', ?, 'admin')`, string(hash))
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	body := `{"username":"demo-admin","password":"Str0ng!Pass"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", jsonReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "admin login: %s", rec.Body.String())
	var out struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.NotEmpty(t, out.Token)
	return out.Token
}

// TestRouter_DemoModeWiringAndRoutes drives the demo-mode wiring: the empty-DB
// seed, the seeded skip on a second build, and both demo routes' handlers.
func TestRouter_DemoModeWiringAndRoutes(t *testing.T) {
	conn := newTestDB(t)

	router, hb, shutdown := NewRouter(conn, demoCfg())
	require.NotNil(t, router)
	t.Cleanup(func() { hb.Stop(); shutdown() })

	// The seed ran on the empty DB: the fictional inventory exists.
	var seeded int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM devices`).Scan(&seeded))
	require.Positive(t, seeded, "demo seed must populate the empty database")

	token := loginAdmin(t, conn, router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/demo/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"demo": true`)

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/demo/wipe", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "wipe: %s", rec.Body.String())

	// A second router over the now-non-empty DB takes the skip branch.
	router2, hb2, shutdown2 := NewRouter(conn, demoCfg())
	require.NotNil(t, router2)
	t.Cleanup(func() { hb2.Stop(); shutdown2() })
}

// TestRouter_DiscoveryWiring drives the discovery-service wiring branches:
// the default interval fallback, the router_arp + router-resident warning,
// and the seed-evidence nil guard.
func TestRouter_DiscoveryWiring(t *testing.T) {
	conn := newTestDB(t)

	cfg := newTestConfig()
	cfg.Scanner.Discovery.Enabled = true
	cfg.Scanner.Discovery.Interval = 0 // default fallback branch
	cfg.Scanner.Discovery.ARPCache.Enabled = true
	cfg.Scanner.Discovery.RouterARP.Enabled = true
	cfg.Scanner.RouterARP.Routers = []string{"192.168.62.1"}

	router, hb, shutdown := NewRouter(conn, cfg)
	require.NotNil(t, router)
	t.Cleanup(func() { hb.Stop(); shutdown() })
}

// TestRouter_BadFingerprintDirFailsEngineGracefully pins the engine-init
// failure warn: an unparseable fingerprint directory must NOT kill the router
// (scanning is degraded, everything else keeps serving).
func TestRouter_BadFingerprintDirFailsEngineGracefully(t *testing.T) {
	conn := newTestDB(t)

	dir := t.TempDir()
	require.NoError(t, writeFile(filepath.Join(dir, "rules.yaml"), "\tnot: [valid: yaml"))

	cfg := newTestConfig()
	cfg.Scanner.FingerprintPath = dir

	router, hb, shutdown := NewRouter(conn, cfg)
	require.NotNil(t, router, "router must survive a broken fingerprint dir")
	t.Cleanup(func() { hb.Stop(); shutdown() })

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	require.Equal(t, http.StatusOK, rec.Code)
}
