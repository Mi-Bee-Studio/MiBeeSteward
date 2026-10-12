// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package middleware_test

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/testutil"
)

// The network-origin read-only fence (#379): devices living in a network
// managed by a reporting agent or a federated peer center (networks.agent_id
// non-empty) are MIRRORS — every hand edit would be overwritten by the next
// report wave, so every mutating route rejects them with 403. Local admin is
// equally fenced (RBAC is orthogonal; origin is the wall).

func seedFenceFixtures(t *testing.T, conn *sql.DB) (localDev, remoteDev, hbCfgRemote int64) {
	t.Helper()
	exec := func(q string, args ...any) int64 {
		res, err := conn.Exec(q, args...)
		require.NoError(t, err)
		id, _ := res.LastInsertId()
		return id
	}
	exec(`INSERT INTO networks (id, name, cidr, agent_id) VALUES (1, 'lan-local', '10.1.0.0/24', NULL)`)
	exec(`INSERT INTO networks (id, name, cidr, agent_id) VALUES (2, 'lan-peer', '10.2.0.0/24', 'peer-center-a')`)
	localDev = exec(`INSERT INTO devices (name, type, ip_address, mac_address, status, device_uuid, network_id)
		VALUES ('mine', 'pc', '10.1.0.5', 'aa:bb:cc:00:00:01', 'online', 'fence-local', 1)`)
	remoteDev = exec(`INSERT INTO devices (name, type, ip_address, mac_address, status, device_uuid, network_id)
		VALUES ('mirror', 'pc', '10.2.0.5', 'aa:bb:cc:00:00:02', 'online', 'fence-remote', 2)`)
	hbCfgRemote = exec(`INSERT INTO heartbeat_configs (device_id, method, target, interval_seconds, timeout_seconds, enabled)
		VALUES (?, 'icmp', '10.2.0.5', 60, 3, 1)`, remoteDev)
	return
}

func fenceServer(t *testing.T) (*httptest.Server, int64, int64, int64) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	localDev, remoteDev, hbCfg := seedFenceFixtures(t, conn)

	r := chi.NewRouter()
	// Device-keyed routes (the :id param is the device).
	r.Route("/devices/{id}", func(r chi.Router) {
		r.Use(middleware.RejectRemoteNetworkWrite(conn))
		r.Put("/", fenceOkHandler)
		r.Delete("/", fenceOkHandler)
		r.Post("/systems", fenceOkHandler)
	})
	// Config-keyed routes (the :id param is the heartbeat config).
	r.Route("/heartbeat-configs/{id}", func(r chi.Router) {
		r.Use(middleware.RejectRemoteNetworkWriteFor(middleware.FenceTargetHeartbeatConfig, conn))
		r.Put("/", fenceOkHandler)
		r.Delete("/", fenceOkHandler)
	})
	server := httptest.NewServer(r)
	t.Cleanup(server.Close)
	return server, localDev, remoteDev, hbCfg
}

func fenceOkHandler(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

func TestRejectRemoteNetworkWrite_DeviceKeyed(t *testing.T) {
	server, localDev, remoteDev, _ := fenceServer(t)

	req, _ := http.NewRequest(http.MethodPut, server.URL+"/devices/"+itoa(localDev), nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "locally-managed device stays editable")

	req, _ = http.NewRequest(http.MethodPut, server.URL+"/devices/"+itoa(remoteDev), nil)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "peer-mirrored device is read-only")

	req, _ = http.NewRequest(http.MethodDelete, server.URL+"/devices/"+itoa(remoteDev), nil)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestRejectRemoteNetworkWrite_HeartbeatConfigKeyed(t *testing.T) {
	server, _, _, hbCfg := fenceServer(t)

	req, _ := http.NewRequest(http.MethodDelete, server.URL+"/heartbeat-configs/"+itoa(hbCfg), nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "heartbeat config of a mirrored device is read-only")
}

// The batch guard: any id in the batch belonging to an agent-managed network
// rejects the whole batch (all-or-nothing, like every other validation).
func TestRemoteManagedDeviceIDs(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	localDev, remoteDev, _ := seedFenceFixtures(t, conn)

	ctx := context.Background()
	remote, err := middleware.RemoteManagedDeviceIDs(ctx, conn, []int64{localDev})
	require.NoError(t, err)
	require.Empty(t, remote)

	remote, err = middleware.RemoteManagedDeviceIDs(ctx, conn, []int64{localDev, remoteDev})
	require.NoError(t, err)
	require.Equal(t, []int64{remoteDev}, remote)
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
