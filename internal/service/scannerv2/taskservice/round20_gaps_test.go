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
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// TestResolveNetworkFromTargets_Matrix pins the targets→network resolution
// contract: only a SINGLE CIDR that matches a networks.cidr resolves; comma
// lists / single IPs / unmatched CIDRs stay unscoped. Both the canonical
// (ipNet.String()) and the raw stored form are tried.
func TestResolveNetworkFromTargets_Matrix(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	// Seed one network with a canonical cidr.
	res, err := conn.Exec(`INSERT INTO networks (name, cidr, created_at, updated_at) VALUES ('n1', '192.168.50.0/24', datetime('now'), datetime('now'))`)
	require.NoError(t, err)
	netID, err := res.LastInsertId()
	require.NoError(t, err)

	// Multi-token targets → unscoped, no error.
	id, err := ResolveNetworkFromTargets(ctx, conn, "192.168.50.0/24, 192.168.51.0/24")
	require.NoError(t, err)
	require.False(t, id.Valid)

	// Non-CIDR (single IP / hostname / range) → unscoped.
	for _, tgt := range []string{"192.168.50.5", "printer.local", "192.168.50.1-192.168.50.9"} {
		id, err = ResolveNetworkFromTargets(ctx, conn, tgt)
		require.NoError(t, err, tgt)
		require.False(t, id.Valid, tgt)
	}

	// Canonical match → resolves.
	id, err = ResolveNetworkFromTargets(ctx, conn, "192.168.50.0/24")
	require.NoError(t, err)
	require.True(t, id.Valid)
	require.Equal(t, netID, id.Int64)

	// Non-canonical stored form (host bits set): ParseCIDR normalizes the
	// target so candidate 1 (ipNet.String()) misses, but candidate 2 (the raw
	// target string) matches the stored cidr verbatim.
	_, err = conn.Exec(`UPDATE networks SET cidr='192.168.50.10/24' WHERE id=?`, netID)
	require.NoError(t, err)
	id, err = ResolveNetworkFromTargets(ctx, conn, "192.168.50.10/24")
	require.NoError(t, err)
	require.True(t, id.Valid, "raw (non-canonical) stored cidr must match by raw form")

	// Unmatched CIDR → unscoped.
	id, err = ResolveNetworkFromTargets(ctx, conn, "203.0.113.0/24")
	require.NoError(t, err)
	require.False(t, id.Valid)
}

// TestTaskService_ListClampsAndScopedPath covers the ListTasks pagination
// clamps, the restricted-scope SQL path (listTasksScoped), and the
// taskNetworkInScope guard matrix (global / missing task / granted vs not).
func TestTaskService_ListClampsAndScopedPath(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	queries := db.New(conn)

	res, err := conn.Exec(`INSERT INTO networks (name, cidr, created_at, updated_at) VALUES ('nA', '10.10.0.0/24', datetime('now'), datetime('now'))`)
	require.NoError(t, err)
	netA, _ := res.LastInsertId()
	res, err = conn.Exec(`INSERT INTO networks (name, cidr, created_at, updated_at) VALUES ('nB', '10.20.0.0/24', datetime('now'), datetime('now'))`)
	require.NoError(t, err)
	netB, _ := res.LastInsertId()

	svc := New(queries, conn, nil, false)
	inA, err := svc.CreateTask(ctx, domain.ScanTaskRequest{
		Name: "in-a", Targets: "10.10.0.0/24", CronExpr: "0 3 * * *", Timeout: 60, ConcurrentHosts: 16,
		PipelineConfig: domain.PipelineConfig{ICMP: domain.ICMPConfig{Enabled: true}},
	})
	require.NoError(t, err)
	inB, err := svc.CreateTask(ctx, domain.ScanTaskRequest{
		Name: "in-b", Targets: "10.20.0.0/24", CronExpr: "0 3 * * *", Timeout: 60, ConcurrentHosts: 16,
		PipelineConfig: domain.PipelineConfig{ICMP: domain.ICMPConfig{Enabled: true}},
	})
	require.NoError(t, err)

	// Pagination clamps: limit<20 → 20, >100 → 100, negative offset → 0. A
	// global-scope list with tiny/oversized params still succeeds.
	tasks, total, err := svc.ListTasks(ctx, "", 1, -5, domain.Scope{Global: true})
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Len(t, tasks, 2)
	_, _, err = svc.ListTasks(ctx, "in-a", 999, 0, domain.Scope{Global: true})
	require.NoError(t, err)

	// Restricted scope sees only its network's task (nA grant).
	tasks, total, err = svc.ListTasks(ctx, "", 20, 0, domain.Scope{NetworkIDs: []int64{netA}})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, tasks, 1)
	require.Equal(t, inA.ID, tasks[0].ID)

	// Search term applies within the scoped path too.
	tasks, _, err = svc.ListTasks(ctx, "in-b", 20, 0, domain.Scope{NetworkIDs: []int64{netA}})
	require.NoError(t, err)
	require.Empty(t, tasks)

	// taskNetworkInScope guard matrix.
	require.True(t, svc.taskNetworkInScope(ctx, inA.ID, domain.Scope{Global: true}), "global scope allows everything")
	require.False(t, svc.taskNetworkInScope(ctx, 424242, domain.Scope{NetworkIDs: []int64{netA}}), "missing task → out of scope")
	require.True(t, svc.taskNetworkInScope(ctx, inA.ID, domain.Scope{NetworkIDs: []int64{netA, netB}}), "granted network")
	require.False(t, svc.taskNetworkInScope(ctx, inB.ID, domain.Scope{NetworkIDs: []int64{netA}}), "ungranted network")

	// A nil-conn construction (scope disabled) fails OPEN for scoped reads.
	bare := New(queries, nil, nil, false)
	require.True(t, bare.taskNetworkInScope(ctx, inB.ID, domain.Scope{NetworkIDs: []int64{netA}}))
	_, _, err = bare.ListTasks(ctx, "", 20, 0, domain.Scope{NetworkIDs: []int64{netA}})
	require.NoError(t, err)
}

// TestTaskService_UpdateMergeBranches exercises UpdateTask's partial-merge
// branches (nil = keep existing), the pipeline-validation rejection, and the
// enabled toggle both ways.
func TestTaskService_UpdateMergeBranches(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	queries := db.New(conn)
	svc := New(queries, conn, nil, false)

	created, err := svc.CreateTask(ctx, domain.ScanTaskRequest{
		Name: "merge-me", Targets: "10.30.0.0/24", CronExpr: "0 3 * * *", Timeout: 60, ConcurrentHosts: 16,
		PipelineConfig: domain.PipelineConfig{ICMP: domain.ICMPConfig{Enabled: true}},
	})
	require.NoError(t, err)

	strPtr := func(s string) *string { return &s }
	intPtr := func(i int) *int { return &i }

	// Nil fields keep existing values; provided fields overwrite.
	newName := "merged"
	newTimeout := 99
	updated, err := svc.UpdateTask(ctx, created.ID, domain.UpdateScanTaskRequest{
		Name:            &newName,
		Timeout:         &newTimeout,
		GlobalLabels:    strPtr("env=prod"),
		ConcurrentHosts: intPtr(8),
	})
	require.NoError(t, err)
	require.Equal(t, "merged", updated.Name)
	require.Equal(t, "10.30.0.0/24", updated.Targets, "nil targets keep existing")
	require.EqualValues(t, 99, updated.Timeout)
	require.Equal(t, "env=prod", updated.GlobalLabels)
	require.EqualValues(t, 8, updated.ConcurrentHosts)

	// A pipeline config that disables every stage → ValidationError, not 500.
	_, err = svc.UpdateTask(ctx, created.ID, domain.UpdateScanTaskRequest{
		PipelineConfig: &domain.PipelineConfig{},
	})
	require.Error(t, err)
	var verr *ValidationError
	require.ErrorAs(t, err, &verr)

	// Enabled toggle: on (task starts enabled → true→false→true covers both
	// change directions).
	off := false
	updated, err = svc.UpdateTask(ctx, created.ID, domain.UpdateScanTaskRequest{Enabled: &off})
	require.NoError(t, err)
	require.False(t, updated.Enabled)
	on := true
	updated, err = svc.UpdateTask(ctx, created.ID, domain.UpdateScanTaskRequest{Enabled: &on})
	require.NoError(t, err)
	require.True(t, updated.Enabled)

	// CredentialID: non-nil zero CLEARS the binding (explicit-set branch of
	// the pointer merge; nil = preserve is covered by the earlier partial
	// update).
	var zero int64
	_, err = svc.UpdateTask(ctx, created.ID, domain.UpdateScanTaskRequest{CredentialID: &zero})
	require.NoError(t, err)

	// Unknown task → ErrScanTaskNotFound.
	_, err = svc.UpdateTask(ctx, 424242, domain.UpdateScanTaskRequest{})
	require.ErrorIs(t, err, ErrScanTaskNotFound)
}
