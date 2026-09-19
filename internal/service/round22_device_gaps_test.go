// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// TestDeviceService_UpdatePointerMatrix drives Update's optional-field merge:
// every pointer set overwrites; nil keeps the stored value; the
// user-attributes patch merges (and empty-string deletes) keys.
func TestDeviceService_UpdatePointerMatrix(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	svc := NewDeviceService(NewDeviceRepository(conn), nil)
	ctx := context.Background()

	created, err := svc.Create(ctx, domain.CreateDeviceRequest{
		Name: "dev-matrix", Type: "camera", Brand: "Hikvision",
		IPAddress: "192.0.2.10", MACAddress: "02:00:00:00:00:10",
		Model: "DS-2CD", Location: "lobby",
	})
	require.NoError(t, err)

	str := func(s string) *string { return &s }
	updated, err := svc.Update(ctx, created.ID, domain.UpdateDeviceRequest{
		Name:           str("renamed"),
		Type:           str("switch"),
		Brand:          str("Dahua"),
		Model:          str("NVR5xxx"),
		Location:       str("server-room"),
		Purpose:        str("recording"),
		Description:    str("matrix test"),
		IPAddress:      str("192.0.2.11"),
		MACAddress:     str("02:00:00:00:00:11"),
		SerialNumber:   str("SN-42"),
		PurchaseDate:   str("2026-01-02"),
		WarrantyExpiry: str("2029-01-02"),
		Tags:           str("a,b"),
	})
	require.NoError(t, err)
	require.Equal(t, "renamed", updated.Name)
	require.Equal(t, "switch", updated.Type)
	require.Equal(t, "Dahua", updated.Brand)
	require.Equal(t, "192.0.2.11", updated.IPAddress)
	require.Equal(t, "SN-42", updated.SerialNumber)
	require.Equal(t, "2026-01-02", updated.PurchaseDate)
	require.Equal(t, "2029-01-02", updated.WarrantyExpiry)

	// A nil-everything update is a no-op rewrite of the same values.
	updated2, err := svc.Update(ctx, created.ID, domain.UpdateDeviceRequest{})
	require.NoError(t, err)
	require.Equal(t, "renamed", updated2.Name)
	require.Equal(t, "192.0.2.11", updated2.IPAddress)

	// User-attributes patch: merge one key, delete another.
	updated3, err := svc.Update(ctx, created.ID, domain.UpdateDeviceRequest{
		UserAttributesPatch: domain.UserAttributes{"rack": "B7", "purpose": ""},
	})
	require.NoError(t, err)
	require.Equal(t, "B7", updated3.UserAttributes["rack"])
	require.Empty(t, updated3.UserAttributes["purpose"], "empty-string patch value deletes the key")

	// Unknown device → ErrDeviceNotFound.
	_, err = svc.Update(ctx, 424242, domain.UpdateDeviceRequest{Name: str("x")})
	require.ErrorIs(t, err, ErrDeviceNotFound)

	// Delete happy + missing.
	require.NoError(t, svc.Delete(ctx, created.ID))
	require.ErrorIs(t, svc.Delete(ctx, created.ID), ErrDeviceNotFound)
}

// TestDeviceService_ListClampsAndFilters covers the filter clamping and the
// status/type/network filter branches over a seeded set.
func TestDeviceService_ListClampsAndFilters(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	svc := NewDeviceService(NewDeviceRepository(conn), nil)
	ctx := context.Background()
	for i, spec := range []struct{ name, typ, status string }{
		{"a", "camera", "online"}, {"b", "camera", "offline"}, {"c", "switch", "unknown"},
	} {
		_, err := svc.Create(ctx, domain.CreateDeviceRequest{
			Name: spec.name, Type: spec.typ,
			IPAddress: "192.0.2." + string(rune('2'+i)), MACAddress: "02:00:00:00:01:0" + string(rune('0'+i)),
		})
		require.NoError(t, err)
		// Status is not part of CreateRequest — set it directly for the filter test.
		_, err = conn.Exec(`UPDATE devices SET status = ? WHERE name = ?`, spec.status, spec.name)
		require.NoError(t, err)
	}

	// Clamp guards: zero limit → 20, negative offset → 0, oversized limit →
	// 100 — none of them error.
	resp, err := svc.List(ctx, domain.DeviceFilter{Limit: 0, Offset: -5})
	require.NoError(t, err)
	require.Len(t, resp.Devices, 3)
	resp, err = svc.List(ctx, domain.DeviceFilter{Limit: 9999})
	require.NoError(t, err)
	require.Len(t, resp.Devices, 3)
	require.EqualValues(t, 3, resp.Total)

	// Status filter narrows; type filter narrows; combined is the intersection.
	resp, err = svc.List(ctx, domain.DeviceFilter{Status: "online"})
	require.NoError(t, err)
	require.Len(t, resp.Devices, 1)
	resp, err = svc.List(ctx, domain.DeviceFilter{Type: "camera"})
	require.NoError(t, err)
	require.Len(t, resp.Devices, 2)
	resp, err = svc.List(ctx, domain.DeviceFilter{Type: "camera", Status: "offline"})
	require.NoError(t, err)
	require.Len(t, resp.Devices, 1)

	// Search matches name substring.
	resp, err = svc.List(ctx, domain.DeviceFilter{Search: "a"})
	require.NoError(t, err)
	require.NotZero(t, resp.Total)
}

// TestDeviceService_CreateWithHeartbeatConfig pins the auto-created heartbeat
// config when a device with an IP is created while a heartbeat service is
// wired (the production wiring path).
func TestDeviceService_CreateWithHeartbeatConfig(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	store, err := OpenHeartbeatStore(filepath.Join(t.TempDir(), "hb.db"))
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })
	hb := NewHeartbeatService(conn, store, &config.Config{})

	svc := NewDeviceService(NewDeviceRepository(conn), hb)
	created, err := svc.Create(context.Background(), domain.CreateDeviceRequest{
		Name: "with-hb", Type: "camera", IPAddress: "192.0.2.99", MACAddress: "02:00:00:00:02:99",
	})
	require.NoError(t, err)

	cfgs, err := hb.GetQueries().ListHeartbeatConfigsByDevice(context.Background(), created.ID)
	require.NoError(t, err)
	require.NotEmpty(t, cfgs, "creating a device with an IP must auto-create its heartbeat config")

	// A device WITHOUT an IP skips the auto-create.
	noIP, err := svc.Create(context.Background(), domain.CreateDeviceRequest{Name: "no-ip", Type: "other"})
	require.NoError(t, err)
	cfgs2, err := hb.GetQueries().ListHeartbeatConfigsByDevice(context.Background(), noIP.ID)
	require.NoError(t, err)
	require.Empty(t, cfgs2)
}
