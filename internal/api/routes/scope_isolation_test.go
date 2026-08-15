// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.

package routes

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/jwtauth/v5"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/domain"
)

// tokenForUser signs a JWT carrying a specific user_id + role (tokenForRole in
// scanner_rbac_test.go pins user_id=1; the scope tests need user_id=2 for the
// seeded admin).
func tokenForUser(t *testing.T, secret string, userID int64, role string) string {
	t.Helper()
	auth := jwtauth.New("HS256", []byte(secret), nil)
	_, token, err := auth.Encode(map[string]any{"user_id": float64(userID), "role": role})
	require.NoError(t, err)
	return token
}

// These tests pin object-level network scope (#138 Phase 2): in closed mode a
// non-admin user sees only the devices on networks they hold a grant for
// (device list filtered; device detail/sub-resources 403 out of scope), while
// admin and open mode are unrestricted. They exercise the REAL NewRouter with a
// closed-mode config and a seeded grant.

// scopeTestDB seeds two networks, a device on each, a viewer user, and (when
// granted) a grant for network 1 only.
func scopeTestDB(t *testing.T, grantNetwork1 bool) *sql.DB {
	t.Helper()
	db := newTestDB(t)
	_, err := db.Exec(`
		INSERT INTO networks (id, name, cidr) VALUES (1, 'lan-1', '10.0.1.0/24'), (2, 'lan-2', '10.0.2.0/24');
		INSERT INTO devices (id, name, ip_address, type, status, network_id) VALUES
			(10, 'dev-in-net1', '10.0.1.5', 'pc', 'online', 1),
			(20, 'dev-in-net2', '10.0.2.5', 'pc', 'online', 2);
		INSERT INTO users (id, username, email, password_hash, role) VALUES
			(1, 'viewer1', 'v1@example.com', 'x', 'viewer'),
			(2, 'admin1', 'a1@example.com', 'x', 'admin');
	`)
	require.NoError(t, err)
	if grantNetwork1 {
		_, err = db.Exec(`INSERT INTO user_network_grants (user_id, network_id) VALUES (1, 1)`)
		require.NoError(t, err)
	}
	return db
}

func closedTestConfig() *config.Config {
	cfg := newTestConfig()
	cfg.RBAC.ScopeDefault = string(domain.ScopeModeClosed)
	return cfg
}

type deviceListJSON struct {
	Devices []struct {
		ID        int64  `json:"id"`
		NetworkID *int64 `json:"network_id"`
	} `json:"devices"`
	Total int `json:"total"`
}

// TestScope_ClosedMode_ViewerSeesOnlyGrantedNetwork: a viewer granted network 1
// lists only network-1 devices and is 403'd on a network-2 device.
func TestScope_ClosedMode_ViewerSeesOnlyGrantedNetwork(t *testing.T) {
	cfg := closedTestConfig()
	db := scopeTestDB(t, true)
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() { heartbeatSvc.Stop(); shutdown() })

	tok := tokenForRole(t, cfg.Auth.JWTSecret, "viewer") // user_id=1, role=viewer

	// List: only the network-1 device (id 10) should appear.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.Equalf(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())

	var body deviceListJSON
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, 1, body.Total, "scoped viewer should see exactly 1 device (network 1)")
	require.Len(t, body.Devices, 1)
	require.Equal(t, int64(10), body.Devices[0].ID)

	// In-scope device detail: passes the gate (handler then 200s).
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/devices/10", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.NotEqual(t, http.StatusForbidden, rec.Code)
	require.NotEqual(t, http.StatusUnauthorized, rec.Code)

	// Out-of-scope device detail: 403.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/devices/20", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code, "scoped viewer must be 403 on network-2 device")

	// Out-of-scope sub-resource: also 403 (ValidateDeviceScope covers sub-resources).
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/devices/20/neighbors", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code, "scoped viewer must be 403 on network-2 sub-resource")
}

// TestScope_ClosedMode_ViewerWithNoGrantsSeesNothing: closed mode + no grants →
// the device list is empty (fail-closed, not fail-open).
func TestScope_ClosedMode_ViewerWithNoGrantsSeesNothing(t *testing.T) {
	cfg := closedTestConfig()
	db := scopeTestDB(t, false) // no grants
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() { heartbeatSvc.Stop(); shutdown() })

	tok := tokenForRole(t, cfg.Auth.JWTSecret, "viewer")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body deviceListJSON
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, 0, body.Total, "closed-mode viewer with no grants sees no devices")
}

// TestScope_AdminBypassesScope: even in closed mode, admin sees every device.
func TestScope_AdminBypassesScope(t *testing.T) {
	cfg := closedTestConfig()
	db := scopeTestDB(t, true)
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() { heartbeatSvc.Stop(); shutdown() })

	// admin1 is user_id=2 in the seed.
	tok := tokenForUser(t, cfg.Auth.JWTSecret, 2, "admin")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body deviceListJSON
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, 2, body.Total, "admin bypasses scope — sees both networks' devices")
}

// TestScope_OpenMode_ViewerSeesEverything: open mode (default) ignores grants —
// a viewer sees all devices regardless of grants. Backward-compatible default.
func TestScope_OpenMode_ViewerSeesEverything(t *testing.T) {
	cfg := newTestConfig() // open mode (default)
	cfg.RBAC.ScopeDefault = string(domain.ScopeModeOpen)
	db := scopeTestDB(t, false)
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() { heartbeatSvc.Stop(); shutdown() })

	tok := tokenForRole(t, cfg.Auth.JWTSecret, "viewer")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var body deviceListJSON
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, 2, body.Total, "open mode: viewer sees all devices")
}

// authedGet fires an authenticated GET through the router and returns the recorder.
func authedGet(t *testing.T, h http.Handler, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	h.ServeHTTP(rec, req)
	return rec
}

// TestScope_ClosedMode_ReadSurfacesScoped pins the Phase 2b surfaces: in closed
// mode a viewer granted network 1 sees ONLY network-1 data across topology,
// changes, dashboard overview, device stats, and device export — while admin is
// unrestricted. This closes the object-scope loop on every read surface that
// joins the devices/change_log tables by network_id.
func TestScope_ClosedMode_ReadSurfacesScoped(t *testing.T) {
	cfg := closedTestConfig()
	db := scopeTestDB(t, true) // grant user1 → network 1
	// Richer seed: net2 device offline (so dashboard offline-list + stats differ
	// by network) + a change_log row on each network.
	_, err := db.Exec(`
		UPDATE devices SET status='offline' WHERE id=20;
		INSERT INTO change_log (network_id, change_type, entity_type, entity_id, detected_at) VALUES
			(1, 'device_added', 'device', 10, '2026-01-01T00:00:00Z'),
			(2, 'device_added', 'device', 20, '2026-01-02T00:00:00Z');
	`)
	require.NoError(t, err)
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() { heartbeatSvc.Stop(); shutdown() })

	viewer := tokenForRole(t, cfg.Auth.JWTSecret, "viewer") // user_id=1, granted net1
	admin := tokenForUser(t, cfg.Auth.JWTSecret, 2, "admin")

	// --- topology: scoped viewer sees only the net-1 node (device 10) ---
	topoFor := func(tok string) (ids []int64) {
		rec := authedGet(t, handler, tok, "/api/v1/topology")
		require.Equalf(t, http.StatusOK, rec.Code, "topology body=%s", rec.Body.String())
		var body struct {
			Nodes []struct {
				ID        int64  `json:"id"`
				NetworkID *int64 `json:"network_id"`
			} `json:"nodes"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		for _, n := range body.Nodes {
			ids = append(ids, n.ID)
		}
		return ids
	}
	require.ElementsMatch(t, []int64{10}, topoFor(viewer), "scoped viewer topology: only net-1 device")
	require.ElementsMatch(t, []int64{10, 20}, topoFor(admin), "admin topology: both devices")

	// --- changes: scoped viewer sees only the net-1 change ---
	changesFor := func(tok string) (total int, nets []int64) {
		rec := authedGet(t, handler, tok, "/api/v1/changes")
		require.Equalf(t, http.StatusOK, rec.Code, "changes body=%s", rec.Body.String())
		var body struct {
			Changes []struct {
				NetworkID *int64 `json:"network_id"`
			} `json:"changes"`
			Total int `json:"total"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		for _, c := range body.Changes {
			if c.NetworkID != nil {
				nets = append(nets, *c.NetworkID)
			}
		}
		return body.Total, nets
	}
	vTotal, vNets := changesFor(viewer)
	require.Equal(t, 1, vTotal, "scoped viewer changes: only net-1 change")
	require.ElementsMatch(t, []int64{1}, vNets)
	aTotal, _ := changesFor(admin)
	require.Equal(t, 2, aTotal, "admin changes: both networks")

	// --- dashboard overview: scoped total == 1, offline == 0; admin total == 2, offline == 1 ---
	overviewFor := func(tok string) (total, offline int64) {
		rec := authedGet(t, handler, tok, "/api/v1/dashboard/overview")
		require.Equalf(t, http.StatusOK, rec.Code, "overview body=%s", rec.Body.String())
		var body struct {
			Devices struct {
				Total   int64 `json:"total"`
				Offline int64 `json:"offline"`
			} `json:"devices"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		return body.Devices.Total, body.Devices.Offline
	}
	vTotal2, vOffline := overviewFor(viewer)
	require.Equal(t, int64(1), vTotal2, "scoped dashboard total: only net-1 device")
	require.Equal(t, int64(0), vOffline, "scoped dashboard offline: net2 offline device hidden")
	aTotal2, aOffline := overviewFor(admin)
	require.Equal(t, int64(2), aTotal2)
	require.Equal(t, int64(1), aOffline)

	// --- device stats: scoped by_status reflects only net1 (online:1); admin sees online:1+offline:1 ---
	statsFor := func(tok string) map[string]int64 {
		rec := authedGet(t, handler, tok, "/api/v1/devices/stats")
		require.Equalf(t, http.StatusOK, rec.Code, "stats body=%s", rec.Body.String())
		var body struct {
			ByStatus map[string]int64 `json:"by_status"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		return body.ByStatus
	}
	require.Equal(t, map[string]int64{"online": 1}, statsFor(viewer), "scoped stats: only net-1 (online) device")
	require.Equal(t, map[string]int64{"online": 1, "offline": 1}, statsFor(admin), "admin stats: both")

	// --- device export: scoped CSV contains only net-1 IP; admin contains both ---
	exportFor := func(tok string) string {
		rec := authedGet(t, handler, tok, "/api/v1/devices/export?format=csv")
		require.Equalf(t, http.StatusOK, rec.Code, "export body=%s", rec.Body.String())
		return rec.Body.String()
	}
	vExport := exportFor(viewer)
	require.Contains(t, vExport, "10.0.1.5", "scoped export includes net-1 device IP")
	require.NotContains(t, vExport, "10.0.2.5", "scoped export excludes net-2 device IP")
	aExport := exportFor(admin)
	require.Contains(t, aExport, "10.0.1.5")
	require.Contains(t, aExport, "10.0.2.5")
}

// scannerSeedData adds scan_tasks/runs/results on both networks (plus one
// cross-network task) so the scanner scope test has data to filter. Task 101 →
// net 1, task 202 → net 2, task 303 → NULL (multi-CIDR targets, unscoped).
func scannerSeedData(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO scan_tasks (id, name, targets, network_id, enabled) VALUES
			(101, 'task-net1', '10.0.1.0/24', 1, 1),
			(202, 'task-net2', '10.0.2.0/24', 2, 1),
			(303, 'task-cross', '10.0.1.0/24,10.0.2.0/24', NULL, 1);
		INSERT INTO scan_task_runs (id, task_id, status, total_hosts, alive_hosts) VALUES
			(11, 101, 'completed', 1, 1),
			(22, 202, 'completed', 1, 1);
		INSERT INTO scan_results (id, task_id, run_id, ip, alive) VALUES
			(1001, 101, 11, '10.0.1.5', 1),
			(2002, 202, 22, '10.0.2.5', 1);
	`)
	require.NoError(t, err)
}

// TestScope_ClosedMode_ScannerSurfacesScoped pins the Phase 2c surfaces: in
// closed mode a viewer granted network 1 sees ONLY net-1 tasks/runs/results —
// out-of-scope details return 404 (indistinguishable from absent), and the
// NULL-network (cross-network) task is hidden. Admin sees everything.
func TestScope_ClosedMode_ScannerSurfacesScoped(t *testing.T) {
	cfg := closedTestConfig()
	db := scopeTestDB(t, true) // grant user1 → network 1
	scannerSeedData(t, db)
	handler, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, handler)
	t.Cleanup(func() { heartbeatSvc.Stop(); shutdown() })

	viewer := tokenForRole(t, cfg.Auth.JWTSecret, "viewer") // user_id=1, granted net1
	admin := tokenForUser(t, cfg.Auth.JWTSecret, 2, "admin")

	// --- tasks list: only the net-1 task (cross/NULL task hidden) ---
	tasksFor := func(tok string) (total int, ids []int64) {
		rec := authedGet(t, handler, tok, "/api/v1/scanner/tasks")
		require.Equalf(t, http.StatusOK, rec.Code, "tasks body=%s", rec.Body.String())
		var body struct {
			Tasks []struct {
				ID int64 `json:"id"`
			} `json:"tasks"`
			Total int `json:"total"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		for _, tk := range body.Tasks {
			ids = append(ids, tk.ID)
		}
		return body.Total, ids
	}
	vTotal, vIDs := tasksFor(viewer)
	require.Equal(t, 1, vTotal, "scoped viewer tasks: only net-1 task")
	require.ElementsMatch(t, []int64{101}, vIDs)
	aTotal, aIDs := tasksFor(admin)
	require.Equal(t, 3, aTotal, "admin tasks: all three")
	require.ElementsMatch(t, []int64{101, 202, 303}, aIDs)

	// --- task detail / sub-resources: out-of-scope → 404, in-scope → 200 ---
	require.Equal(t, http.StatusNotFound, authedGet(t, handler, viewer, "/api/v1/scanner/tasks/202").Code)
	require.Equal(t, http.StatusNotFound, authedGet(t, handler, viewer, "/api/v1/scanner/tasks/303").Code)
	require.Equal(t, http.StatusOK, authedGet(t, handler, viewer, "/api/v1/scanner/tasks/101").Code)
	require.Equal(t, http.StatusNotFound, authedGet(t, handler, viewer, "/api/v1/scanner/tasks/202/runs").Code)
	require.Equal(t, http.StatusNotFound, authedGet(t, handler, viewer, "/api/v1/scanner/tasks/202/results").Code)
	require.Equal(t, http.StatusOK, authedGet(t, handler, viewer, "/api/v1/scanner/tasks/101/runs").Code)
	require.Equal(t, http.StatusOK, authedGet(t, handler, admin, "/api/v1/scanner/tasks/202/runs").Code)

	// --- results list: only the net-1 result row ---
	resultsFor := func(tok string) (total int, ips []string) {
		rec := authedGet(t, handler, tok, "/api/v1/scanner/results")
		require.Equalf(t, http.StatusOK, rec.Code, "results body=%s", rec.Body.String())
		var body struct {
			Results []struct {
				IP string `json:"ip"`
			} `json:"results"`
			Total int `json:"total"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		for _, res := range body.Results {
			ips = append(ips, res.IP)
		}
		return body.Total, ips
	}
	vrTotal, vrIPs := resultsFor(viewer)
	require.Equal(t, 1, vrTotal, "scoped viewer results: only net-1 row")
	require.ElementsMatch(t, []string{"10.0.1.5"}, vrIPs)
	arTotal, _ := resultsFor(admin)
	require.Equal(t, 2, arTotal, "admin results: both rows")

	// sorted variant goes through the same scoped path
	rec := authedGet(t, handler, viewer, "/api/v1/scanner/results?sort=ip&order=asc")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "10.0.1.5")
	require.NotContains(t, rec.Body.String(), "10.0.2.5")

	// --- result detail: out-of-scope → 404 ---
	require.Equal(t, http.StatusNotFound, authedGet(t, handler, viewer, "/api/v1/scanner/results/2002").Code)
	require.Equal(t, http.StatusOK, authedGet(t, handler, viewer, "/api/v1/scanner/results/1001").Code)
	require.Equal(t, http.StatusOK, authedGet(t, handler, admin, "/api/v1/scanner/results/2002").Code)

	// --- runs list + detail ---
	runsFor := func(tok string) (total int, ids []int64) {
		rec := authedGet(t, handler, tok, "/api/v1/scanner/runs?limit=20")
		require.Equalf(t, http.StatusOK, rec.Code, "runs body=%s", rec.Body.String())
		var body struct {
			Runs []struct {
				ID int64 `json:"id"`
			} `json:"runs"`
			Total int `json:"total"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		for _, rn := range body.Runs {
			ids = append(ids, rn.ID)
		}
		return body.Total, ids
	}
	vrnTotal, vrnIDs := runsFor(viewer)
	require.Equal(t, 1, vrnTotal, "scoped viewer runs: only net-1 run")
	require.ElementsMatch(t, []int64{11}, vrnIDs)
	arnTotal, _ := runsFor(admin)
	require.Equal(t, 2, arnTotal)
	require.Equal(t, http.StatusNotFound, authedGet(t, handler, viewer, "/api/v1/scanner/runs/22").Code)
	require.Equal(t, http.StatusOK, authedGet(t, handler, viewer, "/api/v1/scanner/runs/11").Code)

	// --- export: out-of-scope task → 404; in-scope → 200 CSV ---
	require.Equal(t, http.StatusNotFound, authedGet(t, handler, viewer, "/api/v1/scanner/results/export?task_id=202").Code)
	rec = authedGet(t, handler, viewer, "/api/v1/scanner/results/export?task_id=101")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "10.0.1.5")

	// --- dashboard scanning section reflects the scope ---
	rec = authedGet(t, handler, viewer, "/api/v1/dashboard/overview")
	require.Equal(t, http.StatusOK, rec.Code)
	var ov struct {
		Scanning struct {
			TasksTotal int64 `json:"tasks_total"`
			RunsTotal  int64 `json:"runs_total"`
		} `json:"scanning"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &ov))
	require.Equal(t, int64(1), ov.Scanning.TasksTotal, "scoped dashboard scanning: 1 task")
	require.Equal(t, int64(1), ov.Scanning.RunsTotal, "scoped dashboard scanning: 1 run")
}
