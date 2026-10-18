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
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// TestService_DeviceBinding pins the device-bound target lifecycle (#606):
// create with a valid device, reject a vanished device, clear the binding
// via device_id=0 on update, and list by device.
func TestService_DeviceBinding(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	svc := New(queries, nil)
	ctx := context.Background()

	res, err := conn.ExecContext(ctx,
		`INSERT INTO devices (name, ip_address, type) VALUES ('web-01', '192.0.2.10', 'server')`)
	require.NoError(t, err)
	devID, err := res.LastInsertId()
	require.NoError(t, err)

	// Create bound to a real device.
	created, err := svc.Create(ctx, domain.ProbeTargetRequest{
		Name: "bound", Module: "http", Target: "http://192.0.2.10:8080/healthz",
		IntervalSeconds: 60, TimeoutSeconds: 5,
		Options:  &domain.ProbeOptions{Keyword: "ok"},
		DeviceID: &devID,
	})
	require.NoError(t, err)
	require.Equal(t, devID, created.DeviceID)
	require.Equal(t, domain.ProbeSourceManual, created.Source)
	require.NotNil(t, created.Options)
	require.Equal(t, "ok", created.Options.Keyword)

	// ListByDevice sees it; the unfiltered list reports source manual.
	byDevice, total, err := svc.ListByDevice(ctx, devID)
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, byDevice, 1)
	require.Equal(t, created.ID, byDevice[0].ID)

	// Binding to a nonexistent device is rejected.
	ghost := int64(99999)
	_, err = svc.Create(ctx, domain.ProbeTargetRequest{
		Name: "ghost-bound", Module: "tcp", Target: "192.0.2.10:22",
		IntervalSeconds: 60, TimeoutSeconds: 5, DeviceID: &ghost,
	})
	require.ErrorContains(t, err, "does not exist")

	// Update: clear the binding with device_id=0, swap options.
	zero := int64(0)
	updated, err := svc.Update(ctx, created.ID, domain.UpdateProbeTargetRequest{
		DeviceID: &zero,
		Options:  &domain.ProbeOptions{ExpectedStatus: []int{204}},
	})
	require.NoError(t, err)
	require.Equal(t, int64(0), updated.DeviceID)
	require.Equal(t, []int{204}, updated.Options.ExpectedStatus)

	// The unbound target disappears from the device listing.
	_, total, err = svc.ListByDevice(ctx, devID)
	require.NoError(t, err)
	require.EqualValues(t, 0, total)
}

// TestService_OptionsRoundTrip pins the options JSON storage contract:
// option-less rows respond with nil options, and a full block survives the
// marshal/unmarshal round trip unchanged.
func TestService_OptionsRoundTrip(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	svc := New(db.New(conn), nil)
	ctx := context.Background()

	plain, err := svc.Create(ctx, validCreate("http", "http://x.example/"))
	require.NoError(t, err)
	require.Nil(t, plain.Options)

	fancy, err := svc.Create(ctx, domain.ProbeTargetRequest{
		Name: "fancy", Module: "dns", Target: "example.com",
		IntervalSeconds: 120, TimeoutSeconds: 5,
		Options: &domain.ProbeOptions{Record: "A", Resolver: "223.5.5.5", ExpectedIPs: []string{"93.184.216.34"}},
	})
	require.NoError(t, err)
	got, err := svc.Get(ctx, fancy.ID)
	require.NoError(t, err)
	require.Equal(t, "A", got.Options.Record)
	require.Equal(t, "223.5.5.5", got.Options.Resolver)
	require.Equal(t, []string{"93.184.216.34"}, got.Options.ExpectedIPs)

	// An options edit that smuggles foreign-module fields is rejected by the
	// merged re-validation.
	bad := domain.ProbeOptions{Keyword: "not for dns"}
	_, err = svc.Update(ctx, fancy.ID, domain.UpdateProbeTargetRequest{Options: &bad})
	require.ErrorContains(t, err, "do not apply")

	// A module switch without an options payload clears the stale options
	// (a partial-update client must not strand the old module's fields).
	newModule := "tcp"
	newTarget := "203.0.113.10:53"
	switched, err := svc.Update(ctx, fancy.ID, domain.UpdateProbeTargetRequest{Module: &newModule, Target: &newTarget})
	require.NoError(t, err)
	require.Equal(t, "tcp", switched.Module)
	require.Nil(t, switched.Options)
}
