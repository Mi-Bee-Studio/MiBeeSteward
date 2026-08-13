// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package configbackup

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/crypto"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2/sshcred"
	"mibee-steward/internal/testutil"
)

// captureRecorder collects emitted events for assertions.
type captureRecorder struct{ events []changedetect.ChangeEvent }

func (r *captureRecorder) Record(_ context.Context, ev changedetect.ChangeEvent) {
	r.events = append(r.events, ev)
}

// setupSvc builds a Service over an in-memory DB seeded with one router device
// bound to an SSH credential. Returns the service, the queries (to read
// device_configs), and a pointer to the mock fetch's "current config" so the
// test can mutate it between sweeps.
func setupSvc(t *testing.T) (*Service, *db.Queries, *string) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	// Force a single pooled connection: :memory: is per-connection (not shared),
	// and runOnce runs a per-row query while the outer rows query holds its conn,
	// which would otherwise route the inner Get to a different empty in-memory DB.
	conn.SetMaxOpenConns(1)
	queries := db.New(conn)
	ctx := context.Background()

	cipher, err := crypto.NewCipher(make([]byte, crypto.MasterKeyLen))
	require.NoError(t, err)
	encSecret, err := cipher.Encrypt("router-pw")
	require.NoError(t, err)
	credID, err := sshcred.Create(ctx, conn, sshcred.WriteParams{
		Name: "r1-ssh", AuthMethod: "password", Username: "admin", SecretEnc: encSecret, Enabled: true,
	})
	require.NoError(t, err)
	// Seed a router bound to the SSH credential.
	_, err = conn.Exec(`INSERT INTO devices (name, type, ip_address, brand, ssh_credential_id) VALUES ('r1','router','10.0.0.1','Cisco',?)`, credID)
	require.NoError(t, err)

	current := "hostname r1\ninterface eth0\n ip address 10.0.0.1/24\n"
	fetchFn := func(_ context.Context, _ string, _ int, _ *sshcred.Credential, _ string, _ time.Duration) (string, string, error) {
		return current, "", nil // fp="" (no TOFU pin in this test)
	}
	rec := &captureRecorder{}
	svc := New(conn, queries, sshcred.New(conn, cipher), rec, fetchFn, time.Hour, time.Second, nil)
	return svc, queries, &current
}

func countConfigs(t *testing.T, queries *db.Queries, deviceID int64) int64 {
	t.Helper()
	// deviceID is 1 (the seeded device) — CountDeviceConfigs takes device_id.
	n, err := queries.CountDeviceConfigs(context.Background(), deviceID)
	require.NoError(t, err)
	return n
}

func TestService_FirstCapture_StoresBaselineNoEvent(t *testing.T) {
	svc, queries, _ := setupSvc(t)
	svc.runOnce(context.Background())

	require.Equal(t, int64(1), countConfigs(t, queries, 1), "first capture stores a baseline version")
	// A capture recorder: no event on the first (baseline) capture.
	require.Empty(t, svc.changeRecorder.(*captureRecorder).events, "first capture emits no change event")
}

func TestService_ChangedCapture_StoresVersionAndEmitsEvent(t *testing.T) {
	svc, queries, current := setupSvc(t)
	svc.runOnce(context.Background()) // baseline

	// Mutate the running-config the mock returns.
	*current = "hostname r1\ninterface eth0\n ip address 10.0.0.2/24\n" // last octet changed
	svc.runOnce(context.Background())

	require.Equal(t, int64(2), countConfigs(t, queries, 1), "changed capture stores a new version")
	rec := svc.changeRecorder.(*captureRecorder)
	require.Len(t, rec.events, 1, "exactly one device_config_changed event")
	require.Equal(t, changedetect.ChangeTypeDeviceConfigChanged, rec.events[0].ChangeType)

	// The new version carries the diff vs the prior one.
	latest, err := queries.GetLatestDeviceConfig(context.Background(), 1)
	require.NoError(t, err)
	require.Contains(t, latest.DiffFromPrev, "- ip address 10.0.0.1/24")
	require.Contains(t, latest.DiffFromPrev, "+ ip address 10.0.0.2/24")
}

func TestService_UnchangedCapture_NoOp(t *testing.T) {
	svc, queries, _ := setupSvc(t)
	svc.runOnce(context.Background()) // baseline
	svc.runOnce(context.Background()) // identical config

	require.Equal(t, int64(1), countConfigs(t, queries, 1), "unchanged capture stores no new version")
	require.Empty(t, svc.changeRecorder.(*captureRecorder).events, "unchanged capture emits no event")
}

// TestService_SkipsDevicesWithoutCred asserts the selection gate: a device with
// no ssh_credential_id is never backed up.
func TestService_SkipsDevicesWithoutCred(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	// A router with NO ssh_credential_id + a PC (wrong type) — neither is a candidate.
	_, err = conn.Exec(`INSERT INTO devices (name, type, ip_address, brand) VALUES ('nobody','router','10.0.0.9','Cisco')`)
	require.NoError(t, err)
	_, err = conn.Exec(`INSERT INTO devices (name, type, ip_address) VALUES ('mypc','pc','10.0.0.10')`)
	require.NoError(t, err)

	called := false
	fetchFn := func(context.Context, string, int, *sshcred.Credential, string, time.Duration) (string, string, error) {
		called = true
		return "", "", nil
	}
	svc := New(conn, queries, sshcred.New(conn, nil), &captureRecorder{}, fetchFn, time.Hour, time.Second, nil)
	svc.runOnce(context.Background())

	require.False(t, called, "no fetch attempted for devices without a bound SSH credential")
}
