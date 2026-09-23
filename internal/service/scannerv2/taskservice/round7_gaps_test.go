// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package taskservice

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

func setupGapService(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return New(sqldb.New(conn), conn, nil, false), conn
}

// TestService_StampTaskNetwork_CreatePath: creating a task whose targets
// resolve to a network stamps network_id (the restricted-scope visibility
// key); an unresolved task stays NULL.
func TestService_StampTaskNetwork_CreatePath(t *testing.T) {
	svc, conn := setupGapService(t)
	ctx := context.Background()

	_, err := conn.Exec(`INSERT INTO networks (name, cidr) VALUES ('lan-51', '192.168.51.0/24')`)
	require.NoError(t, err)

	resp, err := svc.CreateTask(ctx, gapTaskReq("stamped", "192.168.51.0/24"))
	require.NoError(t, err)

	var stamped sql.NullInt64
	require.NoError(t, conn.QueryRow(`SELECT network_id FROM scan_tasks WHERE id=?`, resp.ID).Scan(&stamped))
	require.True(t, stamped.Valid, "single-CIDR task must be stamped with its network")

	// Unresolvable targets stay NULL, no error, no scope key.
	resp2, err := svc.CreateTask(ctx, gapTaskReq("unscoped", "203.0.113.0/24"))
	require.NoError(t, err)
	require.NoError(t, conn.QueryRow(`SELECT network_id FROM scan_tasks WHERE id=?`, resp2.ID).Scan(&stamped))
	require.False(t, stamped.Valid)
}

func gapTaskReq(name, targets string) domain.ScanTaskRequest {
	return domain.ScanTaskRequest{
		Name: name, Targets: targets, CronExpr: "0 3 * * *",
		Timeout: 60, ConcurrentHosts: 16,
		PipelineConfig: domain.PipelineConfig{ICMP: domain.ICMPConfig{Enabled: true}},
	}
}
