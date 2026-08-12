// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package db_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/configdiff"
	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// These tests exercise the generated device_configs store (#137 PR 2: storage
// model) end-to-end against an in-memory DB, and verify the configdiff utility
// (#215) wires in as the diff_from_prev payload. The contracts:
//   - versions are ordered by fetched_at (latest wins),
//   - ListDeviceConfigs omits config_text (the list is metadata-only),
//   - GetDeviceConfig returns the full text by id,
//   - a changed capture stores the unified diff vs the prior version.

func setupDeviceConfigsDB(t *testing.T) (*db.Queries, int64) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	q := db.New(conn)
	// Seed a device row (the device_configs FK target). Only the NOT-NULL
	// columns without defaults need a value; name is the one required field.
	res, err := conn.Exec(`INSERT INTO devices (name, ip_address) VALUES ('r1', '10.0.0.1')`)
	require.NoError(t, err)
	deviceID, err := res.LastInsertId()
	require.NoError(t, err)
	return q, deviceID
}

func hashOf(t *testing.T, text string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func TestDeviceConfigs_CreateAndGetLatest(t *testing.T) {
	q, deviceID := setupDeviceConfigsDB(t)
	ctx := context.Background()

	v1, err := q.CreateDeviceConfig(ctx, db.CreateDeviceConfigParams{
		DeviceID:     deviceID,
		ConfigHash:   hashOf(t, "a"),
		ConfigText:   "hostname r1\n",
		Protocol:     "ssh_show_run",
		DiffFromPrev: "", // first capture has no prior
	})
	require.NoError(t, err)
	require.Equal(t, "ssh_show_run", v1.Protocol)

	latest, err := q.GetLatestDeviceConfig(ctx, deviceID)
	require.NoError(t, err)
	require.Equal(t, v1.ID, latest.ID, "GetLatest returns the most recent capture")
}

func TestDeviceConfigs_ChangedCaptureStoresDiff(t *testing.T) {
	q, deviceID := setupDeviceConfigsDB(t)
	ctx := context.Background()

	old := "hostname r1\ninterface eth0\n ip address 10.0.0.1/24\n"
	updated := "hostname r1\ninterface eth0\n ip address 10.0.0.2/24\n"

	// First capture.
	_, err := q.CreateDeviceConfig(ctx, db.CreateDeviceConfigParams{
		DeviceID: deviceID, ConfigHash: hashOf(t, old), ConfigText: old, Protocol: "ssh_show_run",
	})
	require.NoError(t, err)

	// Second capture: configdiff produces the unified diff vs the prior version,
	// stored as diff_from_prev (the change-detection payload).
	diff := configdiff.MustDiff("v1", old, "v2", updated)
	require.NotEmpty(t, diff, "the two captures differ -> non-empty diff")
	v2, err := q.CreateDeviceConfig(ctx, db.CreateDeviceConfigParams{
		DeviceID:     deviceID,
		ConfigHash:   hashOf(t, updated),
		ConfigText:   updated,
		Protocol:     "ssh_show_run",
		DiffFromPrev: diff,
	})
	require.NoError(t, err)

	// The latest version carries the diff + the new text.
	latest, err := q.GetLatestDeviceConfig(ctx, deviceID)
	require.NoError(t, err)
	require.Equal(t, v2.ID, latest.ID)
	require.Equal(t, updated, latest.ConfigText)
	require.Contains(t, latest.DiffFromPrev, "- ip address 10.0.0.1/24")
	require.Contains(t, latest.DiffFromPrev, "+ ip address 10.0.0.2/24")
}

func TestDeviceConfigs_ListOmitsConfigText(t *testing.T) {
	q, deviceID := setupDeviceConfigsDB(t)
	ctx := context.Background()

	_, err := q.CreateDeviceConfig(ctx, db.CreateDeviceConfigParams{
		DeviceID: deviceID, ConfigHash: hashOf(t, "a"), ConfigText: "hostname r1\n", Protocol: "ssh_show_run",
	})
	require.NoError(t, err)
	_, err = q.CreateDeviceConfig(ctx, db.CreateDeviceConfigParams{
		DeviceID: deviceID, ConfigHash: hashOf(t, "b"), ConfigText: "hostname r2\n", Protocol: "ssh_show_run",
	})
	require.NoError(t, err)

	rows, err := q.ListDeviceConfigs(ctx, db.ListDeviceConfigsParams{
		DeviceID: deviceID, Limit: 50, Offset: 0,
	})
	require.NoError(t, err)
	require.Len(t, rows, 2)
	// The list projection omits config_text — the generated ListDeviceConfigsRow
	// type has NO ConfigText field at all (compile-time guarantee). It still
	// carries the metadata needed for the history list.
	require.NotEmpty(t, rows[0].ConfigHash)
	require.Equal(t, "ssh_show_run", rows[0].Protocol)
	// Ordered newest-first (DESC on fetched_at): the second capture lands first.
	require.Equal(t, hashOf(t, "b"), rows[0].ConfigHash)
	require.Equal(t, hashOf(t, "a"), rows[1].ConfigHash)
}

func TestDeviceConfigs_Count(t *testing.T) {
	q, deviceID := setupDeviceConfigsDB(t)
	ctx := context.Background()

	n, err := q.CountDeviceConfigs(ctx, deviceID)
	require.NoError(t, err)
	require.EqualValues(t, 0, n)

	_, _ = q.CreateDeviceConfig(ctx, db.CreateDeviceConfigParams{
		DeviceID: deviceID, ConfigHash: hashOf(t, "a"), ConfigText: "x", Protocol: "ssh_show_run",
	})
	n, err = q.CountDeviceConfigs(ctx, deviceID)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
}
