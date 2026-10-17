// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

func autogenCfg() config.ProbeAutogenConfig {
	return config.ProbeAutogenConfig{
		Enabled: true, Services: []string{"http", "https"},
		IntervalSeconds: 300, MaxTargets: 100, SweepIntervalMinutes: 15,
	}
}

func setupAutogen(t *testing.T) (*AutogenService, *db.Queries, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	svc := NewAutogenService(queries, autogenCfg(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	return svc, queries, conn
}

// seedDeviceWithServices: one device (uuid + network) whose row carries the
// detected_services JSON both write paths populate. services are name/port
// pairs; port 0 models the hostname-derived portless identities.
func seedDeviceWithServices(t *testing.T, conn *sql.DB, agentID string, services ...[2]string) (deviceID int64) {
	t.Helper()
	ctx := context.Background()
	cidr := "192.0.2.0/24"
	net, err := db.New(conn).CreateNetwork(ctx, db.CreateNetworkParams{Name: "lan-x", Cidr: &cidr})
	require.NoError(t, err)
	if agentID != "" {
		_, err = conn.ExecContext(ctx, `UPDATE networks SET agent_id = ? WHERE id = ?`, agentID, net.ID)
		require.NoError(t, err)
	}
	svcJSON := "["
	for i, svc := range services {
		if i > 0 {
			svcJSON += ","
		}
		svcJSON += fmt.Sprintf(`{"name":%q,"port":%s,"protocol":"tcp"}`, svc[0], svc[1])
	}
	svcJSON += "]"
	res, err := conn.ExecContext(ctx,
		`INSERT INTO devices (device_uuid, name, ip_address, type, network_id, detected_services) VALUES ('uuid-1', 'web-01', '192.0.2.10', 'server', ?, ?)`, net.ID, svcJSON)
	require.NoError(t, err)
	deviceID, err = res.LastInsertId()
	require.NoError(t, err)
	return deviceID
}

func TestAutogenSweep(t *testing.T) {
	ctx := context.Background()

	t.Run("creates device-bound targets with vantage inference", func(t *testing.T) {
		svc, queries, conn := setupAutogen(t)
		devID := seedDeviceWithServices(t, conn, "agent-lan-x", [2]string{"http", "8080"}, [2]string{"ssh", "22"})

		created, _, _, err := svc.Sweep(ctx)
		require.NoError(t, err)
		require.EqualValues(t, 1, created, "only http passes the policy's http+https service filter")

		byName := listAutoTargets(t, queries)
		http := byName[autogenName(devID, "http", 8080)]
		require.Equal(t, "http", http.Module)
		require.Equal(t, "http://192.0.2.10:8080/", http.Target)
		require.Equal(t, domain.ProbeVantageAgentPrefix+"agent-lan-x", http.Vantage)
		require.NotNil(t, http.DeviceID)
		require.Equal(t, devID, *http.DeviceID)
		// ssh is not in the policy's service filter (http+https): no target.
		_, hasSSH := byName[autogenName(devID, "ssh", 22)]
		require.False(t, hasSSH)
	})

	t.Run("center vantage without an agent", func(t *testing.T) {
		svc, queries, conn := setupAutogen(t)
		devID := seedDeviceWithServices(t, conn, "", [2]string{"http", "80"})

		_, _, _, err := svc.Sweep(ctx)
		require.NoError(t, err)
		http := listAutoTargets(t, queries)[autogenName(devID, "http", 80)]
		require.Equal(t, domain.ProbeVantageCenter, http.Vantage)
	})

	t.Run("service disappearance parks, reappearance re-enables", func(t *testing.T) {
		svc, queries, conn := setupAutogen(t)
		devID := seedDeviceWithServices(t, conn, "", [2]string{"http", "80"})
		name := autogenName(devID, "http", 80)
		setServices := func(json string) {
			_, err := conn.ExecContext(ctx, `UPDATE devices SET detected_services = ? WHERE id = ?`, json, devID)
			require.NoError(t, err)
		}

		_, _, _, err := svc.Sweep(ctx)
		require.NoError(t, err)
		require.Equal(t, int64(1), listAutoTargets(t, queries)[name].Enabled)

		// The service leaves the scan → target parked (kept for history).
		setServices("[]")
		_, _, disabled, err := svc.Sweep(ctx)
		require.NoError(t, err)
		require.EqualValues(t, 1, disabled)
		require.Equal(t, int64(0), listAutoTargets(t, queries)[name].Enabled, "parked, not deleted")

		// The same service on the same port returns → the parked row revives.
		setServices(`[{"name":"http","port":80,"protocol":"tcp"}]`)
		_, enabled, _, err := svc.Sweep(ctx)
		require.NoError(t, err)
		require.EqualValues(t, 1, enabled)
		require.Equal(t, int64(1), listAutoTargets(t, queries)[name].Enabled)

		// The service moves to a new port → a NEW target appears; the old one
		// parks again.
		setServices(`[{"name":"http","port":8080,"protocol":"tcp"}]`)
		_, enabled, _, err = svc.Sweep(ctx)
		require.NoError(t, err)
		moved := listAutoTargets(t, queries)[autogenName(devID, "http", 8080)]
		require.Equal(t, int64(1), moved.Enabled)
		require.Equal(t, "http://192.0.2.10:8080/", moved.Target)
		require.Equal(t, int64(0), listAutoTargets(t, queries)[name].Enabled)
		_ = enabled
	})

	t.Run("manual targets are never touched, config off parks autos", func(t *testing.T) {
		svc, queries, conn := setupAutogen(t)
		seedDeviceWithServices(t, conn, "", [2]string{"http", "80"})

		manualSvc := New(queries, nil)
		_, err := manualSvc.Create(ctx, domain.ProbeTargetRequest{
			Name: "my-own", Module: "http", Target: "http://192.0.2.99/",
			IntervalSeconds: 60, TimeoutSeconds: 5,
		})
		require.NoError(t, err)

		_, _, _, err = svc.Sweep(ctx)
		require.NoError(t, err)

		// Config off: autos parked, manual untouched.
		off := autogenCfg()
		off.Enabled = false
		svcOff := NewAutogenService(queries, off, slog.New(slog.NewTextHandler(io.Discard, nil)))
		_, _, disabled, err := svcOff.Sweep(ctx)
		require.NoError(t, err)
		require.EqualValues(t, 1, disabled)
		manual, err := queries.GetProbeTargetByName(ctx, "my-own")
		require.NoError(t, err)
		require.Equal(t, int64(1), manual.Enabled)
		require.Equal(t, domain.ProbeSourceManual, manual.Source)
	})

	t.Run("max_targets caps creation", func(t *testing.T) {
		_, queries, conn := setupAutogen(t)
		capped := autogenCfg()
		capped.MaxTargets = 1
		svcCapped := NewAutogenService(queries, capped, slog.New(slog.NewTextHandler(io.Discard, nil)))
		seedDeviceWithServices(t, conn, "", [2]string{"http", "80"}, [2]string{"https", "443"})

		created, _, _, err := svcCapped.Sweep(ctx)
		require.NoError(t, err)
		require.EqualValues(t, 1, created)
	})
}

func listAutoTargets(t *testing.T, queries *db.Queries) map[string]db.ProbeTarget {
	t.Helper()
	rows, err := queries.ListProbeTargets(context.Background())
	require.NoError(t, err)
	out := make(map[string]db.ProbeTarget)
	for _, r := range rows {
		if r.Source == domain.ProbeSourceAuto {
			out[r.Name] = r
		}
	}
	return out
}
