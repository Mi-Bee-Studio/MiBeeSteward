// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRouter_DiscoveryAllSources drives the discovery wiring with EVERY
// source enabled — each source's constructor + Start + activeSources append
// executes (listeners that cannot bind degrade with a warning, never kill
// the router).
func TestRouter_DiscoveryAllSources(t *testing.T) {
	conn := newTestDB(t)

	cfg := newTestConfig()
	cfg.Scanner.Discovery.Enabled = true
	cfg.Scanner.Discovery.Interval = 2
	cfg.Scanner.Discovery.ARPCache.Enabled = true
	cfg.Scanner.Discovery.DHCPLeases.Enabled = true
	cfg.Scanner.Discovery.Conntrack.Enabled = true
	cfg.Scanner.Discovery.Hostapd.Enabled = true
	cfg.Scanner.Discovery.Hostapd.Interfaces = []string{"wlan0"}
	cfg.Scanner.Discovery.DNSLog.Enabled = true
	cfg.Scanner.Discovery.DNSLog.Path = "/nonexistent/dnsmasq.log"
	cfg.Scanner.Discovery.Multicast.Enabled = true
	cfg.Scanner.Discovery.RouterARP.Enabled = true
	cfg.Scanner.RouterARP.Routers = []string{"192.168.62.1"}
	cfg.Scanner.RouterARP.Community = "router-comm"

	router, hb, shutdown := NewRouter(conn, cfg)
	require.NotNil(t, router)
	t.Cleanup(func() { hb.Stop(); shutdown() })

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	require.Equal(t, http.StatusOK, rec.Code)
}

// TestRouter_DeadDB_SettingsOverlayWarnAndDemoSkip: over a dead handle the
// settings-overlay constructor fails (warn + config-only) and the demo
// seed's emptiness probe fails (treated as non-empty → skip) — the router
// still builds and serves.
func TestRouter_DeadDB_SettingsOverlayWarnAndDemoSkip(t *testing.T) {
	conn := newTestDB(t)

	require.NoError(t, conn.Close())

	dead := newTestConfig()
	dead.Server.DemoMode = true
	router2, hb2, shutdown2 := NewRouter(conn, dead)
	require.NotNil(t, router2, "router must survive a dead handle")
	t.Cleanup(func() { hb2.Stop(); shutdown2() })

	rec := httptest.NewRecorder()
	router2.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	require.Equal(t, http.StatusOK, rec.Code)
}
