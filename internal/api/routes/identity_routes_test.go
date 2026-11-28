// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not accommodate;
// see LICENSE-COMMERCIAL.md.

package routes

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentityRoutesEnforceAuthenticationAndNetworkScope(t *testing.T) {
	cfg := closedTestConfig()
	db := scopeTestDB(t, true)
	_, err := db.Exec(`
		UPDATE devices SET scan_attributes='{"hostname":"Shared-Host.example"}', serial_number='SN-SHARED' WHERE id IN (10, 20);
		INSERT INTO devices (id, name, ip_address, type, status, network_id, device_uuid, scan_attributes, serial_number)
		VALUES (11, 'dev-in-net1-b', '10.0.1.6', 'pc', 'online', 1, 'uuid-scope-1b', '{"hostname":"shared-host"}', 'sn-shared');
	`)
	require.NoError(t, err)
	router, heartbeatSvc, shutdown := NewRouter(db, cfg)
	require.NotNil(t, router)
	t.Cleanup(func() { heartbeatSvc.Stop(); shutdown() })
	viewer := tokenForRole(t, cfg.Auth.JWTSecret, "viewer")
	admin := tokenForUser(t, cfg.Auth.JWTSecret, 2, "admin")

	rec := authedGet(t, router, "", "/api/v1/identity/candidates")
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	rec = authedGet(t, router, viewer, "/api/v1/identity/candidates")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var scoped struct {
		Candidates []struct {
			DeviceA struct {
				NetworkID *int64 `json:"network_id"`
			} `json:"device_a"`
			DeviceB struct {
				NetworkID *int64 `json:"network_id"`
			} `json:"device_b"`
		} `json:"candidates"`
		Summary struct {
			TotalDevices int64 `json:"total_devices"`
		} `json:"summary"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &scoped))
	require.Equal(t, 1, scoped.Total, "viewer sees only the network-1 pair")
	require.Equal(t, int64(2), scoped.Summary.TotalDevices)
	for _, c := range scoped.Candidates {
		require.NotNil(t, c.DeviceA.NetworkID)
		require.Equal(t, int64(1), *c.DeviceA.NetworkID)
		require.NotNil(t, c.DeviceB.NetworkID)
		require.Equal(t, int64(1), *c.DeviceB.NetworkID)
	}

	rec = authedGet(t, router, viewer, "/api/v1/identity/candidates?network_id=2")
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &scoped))
	require.Zero(t, scoped.Total, "an explicit network filter must not widen caller scope")

	rec = authedGet(t, router, viewer, "/api/v1/devices/10/identity")
	require.Equal(t, http.StatusOK, rec.Code, "canonical no-trailing-slash URL: %s", rec.Body.String())
	rec = authedGet(t, router, viewer, "/api/v1/devices/20/identity")
	require.Equal(t, http.StatusForbidden, rec.Code)

	rec = authedGet(t, router, admin, "/api/v1/identity/candidates")
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &scoped))
	require.Equal(t, 3, scoped.Total, "admin may review every scoped-active pair")
	require.Equal(t, int64(3), scoped.Summary.TotalDevices)
}
