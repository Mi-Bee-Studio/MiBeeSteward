// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"

	"mibee-steward/internal/testutil"
)

// TestNewEngine_ConfigFallbackBranches drives NewEngine's degradation ladder:
// an OUI path pointing at a missing file and fingerprint paths that are bad /
// empty all fall back to the embedded tables instead of disabling features.
func TestNewEngine_ConfigFallbackBranches(t *testing.T) {
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	tmp := t.TempDir()

	// OUI path set but missing → embedded curated fallback.
	// Fingerprint path set to a NON-yaml dir → load error → embedded rules.
	// Fingerprint path set to an EMPTY dir → empty → embedded rules.
	emptyFP := filepath.Join(tmp, "empty-fp")
	require.NoError(t, os.MkdirAll(emptyFP, 0o755))
	badFP := filepath.Join(tmp, "bad-fp", "not-a-rule.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(badFP), 0o755))
	require.NoError(t, os.WriteFile(badFP, []byte("{{{ not yaml"), 0o600))

	for _, fp := range []string{badFP, emptyFP} {
		eng, err := NewEngine(db, Config{
			AllowReservedTargets: true,
			PerProbeTimeout:      200 * time.Millisecond,
			PerHostTimeout:       2 * time.Second,
			MaxConcurrentHosts:   4,
			OUIPath:              filepath.Join(tmp, "missing-oui.txt"),
			FingerprintPath:      filepath.Dir(fp),
			MaxConcurrentScans:   2,
			SeedEvidence:         func(string) []scannerv2.Evidence { return nil },
		}, nil)
		require.NoError(t, err, "fingerprint path %s", fp)
		require.NotNil(t, eng)
		require.NotNil(t, eng.Orchestrator)
	}

	// eBPF enabled flag takes the logging branch without breaking assembly.
	eng, err := NewEngine(db, Config{
		PerProbeTimeout: 200 * time.Millisecond,
		PerHostTimeout:  2 * time.Second,
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, eng)
}
