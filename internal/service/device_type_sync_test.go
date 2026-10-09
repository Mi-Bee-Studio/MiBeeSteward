// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// TestDevicesTypeCHECK_InSyncWithDomain is the regression guard for the silent-
// drift risk flagged in M11 (the deeper device_types-lookup-table refactor is
// tracked in #38 and deferred). The set of valid device types lives in TWO
// places that must agree:
//
//  1. internal/domain/device.go, ValidDeviceTypes (the Go single source of truth)
//  2. db/schema.sql, devices.type CHECK(...) (the runtime authority on inserts)
//
// This test probes #2 at runtime: builds the real schema, then for each type in
// domain.ValidDeviceTypes confirms a sentinel INSERT succeeds (CHECK accepts it).
// If anyone adds a TypeXxx constant without updating the schema CHECK, this test
// fails with a clear "type X accepted by Go but rejected by schema CHECK" message.
//
// It does NOT verify the reverse (schema accepts a type Go doesn't), the
// ValidateDeviceType default-to-other behavior makes a schema-only type harmless
// (a host with an unknown-but-CHECK-valid type just won't round-trip through
// Go validation cleanly). The forward direction (Go knows a type the schema
// rejects) is the dangerous one, it causes INSERT failures at runtime.
func TestDevicesTypeCHECK_InSyncWithDomain(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err, "setup test DB from schema")
	t.Cleanup(func() { dbConn.Close() })

	ctx := context.Background()
	for _, typ := range domain.ValidDeviceTypes {
		// Each type must be accepted by the schema's devices.type CHECK. Use a
		// rolled-back tx so the sentinel rows never persist (and so a CHECK
		// failure doesn't leave a half-row that breaks later iterations).
		tx, err := dbConn.BeginTx(ctx, nil)
		require.NoError(t, err, "begin probe tx for type %s", typ)
		_, insertErr := tx.ExecContext(ctx,
			`INSERT INTO devices (name, type) VALUES (?, ?)`,
			"__sync_probe__", string(typ))
		// Roll back regardless of outcome (success or CHECK violation).
		if rbErr := tx.Rollback(); rbErr != nil {
			t.Fatalf("rollback probe tx for type %s: %v", typ, rbErr)
		}
		if insertErr != nil {
			t.Errorf("device type %q is in domain.ValidDeviceTypes but the schema's "+
				"devices.type CHECK rejected it (INSERT error: %v). Add %q to the CHECK "+
				"in db/schema.sql (the only runtime authority on inserts).",
				typ, insertErr, typ)
		}
	}
}
