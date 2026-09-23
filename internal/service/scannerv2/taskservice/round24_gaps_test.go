// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package taskservice

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// TestCreateTask_NilConnSkipsNetworkStamp pins the nil-conn guard in
// stampTaskNetwork: a service built without a raw connection skips the
// stamping (and the scope checks fail open), the task write still succeeds.
func TestCreateTask_NilConnSkipsNetworkStamp(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	svcNoConn := New(db.New(conn), nil, nil, false)

	resp, err := svcNoConn.CreateTask(context.Background(), gapTaskReq("nil-conn-task", "192.168.90.0/24"))
	require.NoError(t, err)
	require.NotZero(t, resp.ID)
}

// TestStampTaskNetwork_DeadConnLogsAndContinues: a dead raw handle makes the
// network resolution fail, the failure is logged and the stamping returns
// without failing the caller.
func TestStampTaskNetwork_DeadConnLogsAndContinues(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	svc := New(nil, conn, nil, false)

	require.NotPanics(t, func() {
		svc.stampTaskNetwork(context.Background(), 1, "192.168.90.0/24", slog.Default())
	})
}

// TestGetTask_DeadDB covers the generic (non-ErrNoRows) error wrap of GetTask.
func TestGetTask_DeadDB(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	svc := New(db.New(conn), nil, nil, false)
	_, err = svc.GetTask(context.Background(), 1, domain.Scope{Global: true})
	require.Error(t, err)
}
