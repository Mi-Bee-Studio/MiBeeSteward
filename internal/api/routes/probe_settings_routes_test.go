// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package routes

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// End-to-end 设置 → 拨测 contract over the REAL router: flipping the probe
// policy switches takes effect immediately (the quality subscriber reseeds
// the system matrix — park on off, revive on on). The handler-level test
// covers request semantics; this one covers the subscriber wiring.
func TestRoutes_ProbeSettingsSwitchReseeds(t *testing.T) {
	cfg := newTestConfig()
	db := newTestDB(t)
	if _, err := db.Exec(`INSERT INTO users (id, username, email, password_hash, role)
		VALUES (1, 'testadmin', 'testadmin@example.com', 'x', 'admin')`); err != nil {
		t.Fatalf("seed principal: %v", err)
	}
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	t.Cleanup(func() {
		heartbeatSvc.Stop()
		shutdown()
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	token := tokenForRole(t, cfg.Auth.JWTSecret, "admin")
	do := func(method, path, body string) (*http.Response, []byte) {
		var rdr io.Reader
		if body != "" {
			rdr = bytes.NewBufferString(body)
		}
		req, err := http.NewRequest(method, server.URL+path, rdr)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := server.Client().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp, data
	}

	type probeTarget struct {
		Source  string `json:"source"`
		Enabled bool   `json:"enabled"`
	}
	listSystem := func() []probeTarget {
		_, data := do(http.MethodGet, "/api/v1/probe-targets?limit=100", "")
		var payload struct {
			Targets []probeTarget `json:"targets"`
		}
		require.NoError(t, json.Unmarshal(data, &payload), string(data))
		var out []probeTarget
		for _, tgt := range payload.Targets {
			if tgt.Source == "system" {
				out = append(out, tgt)
			}
		}
		return out
	}

	// Baseline: default-on config seeded the matrix at boot.
	resp, data := do(http.MethodGet, "/api/v1/settings/probes", "")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(data))
	require.Contains(t, string(data), `"quality_source":"config"`)
	require.Contains(t, string(data), `"enabled":true`)

	base := listSystem()
	require.NotEmpty(t, base, "matrix seeded at boot")
	for _, tgt := range base {
		require.True(t, tgt.Enabled)
	}

	// Flip OFF: subscriber reseeds → system rows park.
	resp, data = do(http.MethodPut, "/api/v1/settings/probes", `{"quality":{"enabled":false}}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(data))
	parked := listSystem()
	require.Len(t, parked, len(base))
	for _, tgt := range parked {
		require.False(t, tgt.Enabled, "switch-off parks every system row")
	}

	// Flip ON: rows revive (the old bug left them parked until hand-deleted).
	resp, data = do(http.MethodPut, "/api/v1/settings/probes", `{"quality":{"enabled":true}}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(data))
	revived := listSystem()
	require.Len(t, revived, len(base))
	for _, tgt := range revived {
		require.True(t, tgt.Enabled, "switch-on revives parked system rows")
	}
}

// The LAN empty state's one-click sweep rides POST /probe-targets/autogen-sweep:
// on an empty (no discovered services) store the sweep is a harmless no-op that
// still reports its zero counts.
func TestRoutes_AutogenSweepNow(t *testing.T) {
	cfg := newTestConfig()
	db := newTestDB(t)
	if _, err := db.Exec(`INSERT INTO users (id, username, email, password_hash, role)
		VALUES (1, 'testadmin', 'testadmin@example.com', 'x', 'admin')`); err != nil {
		t.Fatalf("seed principal: %v", err)
	}
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	t.Cleanup(func() {
		heartbeatSvc.Stop()
		shutdown()
	})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	token := tokenForRole(t, cfg.Auth.JWTSecret, "admin")
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/probe-targets/autogen-sweep", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := server.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var payload struct {
		Created  int `json:"created"`
		Enabled  int `json:"enabled"`
		Disabled int `json:"disabled"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))
	require.Zero(t, payload.Created)
	require.Zero(t, payload.Enabled)
	require.Zero(t, payload.Disabled)
}
