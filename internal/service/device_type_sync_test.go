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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// readAgentMainSource loads cmd/agent/main.go relative to this test file's
// package directory (internal/service → ../../cmd/agent/main.go). Returns an
// error (which the caller turns into a t.Skip) when the path can't be resolved
// — keeps the test working from the repo root and degrades gracefully where
// source isn't co-located.
func readAgentMainSource() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", os.ErrNotExist
	}
	agentPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "cmd", "agent", "main.go")
	b, err := os.ReadFile(agentPath)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// extractFirstCHECK finds the first "CHECK(type IN (...))" clause in src and
// returns its inner contents (up to the first ')'). "" when not found. Used to
// compare the agent's devices.type CHECK against domain.ValidDeviceTypes
// without pulling in a SQL parser.
func extractFirstCHECK(src string) string {
	idx := strings.Index(src, "CHECK(type IN")
	if idx < 0 {
		return ""
	}
	rest := src[idx:]
	end := strings.IndexByte(rest, ')')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// TestDevicesTypeCHECK_InSyncWithDomain is the regression guard for the silent-
// drift risk flagged in M11 (the deeper device_types-lookup-table refactor is
// tracked in #38 and deferred). The set of valid device types lives in THREE
// places that must agree:
//
//  1. internal/domain/device.go — ValidDeviceTypes (the Go single source of truth)
//  2. db/schema.sql — devices.type CHECK(...) (the runtime authority on inserts)
//  3. cmd/agent/main.go agentSchema — the agent's mini-schema CHECK (mirror of #2)
//
// This test probes #2 at runtime: builds the real schema, then for each type in
// domain.ValidDeviceTypes confirms a sentinel INSERT succeeds (CHECK accepts it).
// If anyone adds a TypeXxx constant without updating the schema CHECK, this test
// fails with a clear "type X accepted by Go but rejected by schema CHECK" message.
//
// It does NOT verify the reverse (schema accepts a type Go doesn't) — the
// ValidateDeviceType default-to-other behavior makes a schema-only type harmless
// (a host with an unknown-but-CHECK-valid type just won't round-trip through
// Go validation cleanly). The forward direction (Go knows a type the schema
// rejects) is the dangerous one — it causes INSERT failures at runtime.
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
				"in db/schema.sql (the agent's mini-schema intentionally has no CHECK on "+
				"type — it's a permissive shadow — so only the center schema needs updating).",
				typ, insertErr, typ)
		}
	}
}

// TestDevicesTypeCHECK_AgentSchemaAcceptsAllDomainTypes confirms the agent's
// mini-schema (cmd/agent/main.go agentSchema) does NOT have a tighter type
// constraint than the center. The agent's devices table intentionally carries
// NO CHECK on `type` (its DB is a local shadow that just forwards reports
// upstream — type validation is the center's job, not the agent's), so every
// domain.ValidDeviceTypes value must INSERT cleanly there. This guards against
// someone accidentally adding a CHECK to the agent schema that's narrower than
// the domain set, which would silently drop agent reports of new device types.
func TestDevicesTypeCHECK_AgentSchemaAcceptsAllDomainTypes(t *testing.T) {
	agentSrc, err := readAgentMainSource()
	if err != nil {
		t.Skipf("could not read cmd/agent/main.go source (path-dependent; skipping): %v", err)
	}
	// The agent's devices table deliberately has no CHECK on type. If one is
	// ever added (extractFirstCHECK returns non-empty), it must list every
	// domain type — assert that forward direction. Empty result = no CHECK =
	// the intended permissive shadow, which trivially accepts all types.
	if agentCHECK := extractFirstCHECK(agentSrc); agentCHECK != "" {
		for _, typ := range domain.ValidDeviceTypes {
			needle := "'" + string(typ) + "'"
			if !strings.Contains(agentCHECK, needle) {
				t.Errorf("device type %q is in domain.ValidDeviceTypes but MISSING from the "+
					"agent's devices.type CHECK in cmd/agent/main.go. Either add it there or "+
					"drop the agent's CHECK (the agent's DB is a shadow; type validation is "+
					"the center's job).", typ)
			}
		}
	}
	// No CHECK → nothing more to verify (all types accepted by construction).
}
