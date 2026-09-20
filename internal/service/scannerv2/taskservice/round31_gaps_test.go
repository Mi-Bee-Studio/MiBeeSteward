// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package taskservice

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// TestListTasks_DeadDB pins the list/count error wraps (global + scoped
// variants) on a dead handle.
func TestListTasks_DeadDB(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	svc := New(db.New(conn), conn, nil, false)
	ctx := context.Background()

	_, _, err = svc.ListTasks(ctx, "", 20, 0, domain.Scope{Global: true})
	require.Error(t, err)

	_, _, err = svc.ListTasks(ctx, "", 20, 0, domain.Scope{NetworkIDs: []int64{1}})
	require.Error(t, err)
}

// TestListTasks_SearchAndClamps drives the live-DB list paths: the
// case-insensitive search filter narrows both rows and total, and limits
// clamp instead of going negative.
func TestListTasks_SearchAndClamps(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	svc := New(db.New(conn), conn, nil, false)
	ctx := context.Background()

	_, err = svc.CreateTask(ctx, gapTaskReq("alpha-scan", "192.168.80.0/24"))
	require.NoError(t, err)
	_, err = svc.CreateTask(ctx, gapTaskReq("beta-scan", "192.168.81.0/24"))
	require.NoError(t, err)

	rows, total, err := svc.ListTasks(ctx, "ALPHA", 20, 0, domain.Scope{Global: true})
	require.NoError(t, err)
	require.EqualValues(t, 1, total, "search matches case-insensitively")
	require.Len(t, rows, 1)
	require.Equal(t, "alpha-scan", rows[0].Name)

	// Zero/negative limit clamps to the default page size.
	rows, _, err = svc.ListTasks(ctx, "", -5, -1, domain.Scope{Global: true})
	require.NoError(t, err)
	require.Len(t, rows, 2)
}
