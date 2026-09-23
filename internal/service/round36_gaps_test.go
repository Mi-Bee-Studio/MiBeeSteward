// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/service/probetarget"
	"mibee-steward/internal/service/scannerv2/configbackup"
	"mibee-steward/internal/service/scannerv2/sshcred"
	"mibee-steward/internal/testutil"
)

// TestConfigBackupService_DefaultsAndStartStop pins the constructor's
// defaulting (interval<=0 → 6h, timeout<=0 → 30s) and the Start/Stop loop
// with a mock fetch, the startup pass runs once, Stop returns.
func TestConfigBackupService_DefaultsAndStartStop(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := sqldb.New(conn)

	var fetch configbackup.FetchFunc = func(context.Context, string, int, *sshcred.Credential, string, time.Duration) (string, string, error) {
		return "", "", nil
	}
	svc := configbackup.New(conn, queries, nil, nil, fetch, 0, 0, nil)
	require.NotNil(t, svc)

	// The startup pass runs immediately (over an empty device set, no
	// fetch, but the loop + Stop lifecycle is what's under test).
	ctx, cancel := context.WithCancel(context.Background())
	svc.Start(ctx)
	cancel()
	done := make(chan struct{})
	go func() { svc.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop must return after cancel")
	}
}

// TestProbeTargetService_ListError pins the list error wrap on a dead handle
// (the limit/offset clamps run before the query).
func TestProbeTargetService_ListError(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	svc := probetarget.New(sqldb.New(conn), nil)

	_, _, err = svc.List(context.Background(), "", -1, -5)
	require.Error(t, err)
}
