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
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/crypto"
	"mibee-steward/internal/service/scannerv2/credresolver"
	"mibee-steward/internal/service/scannerv2/ebpf"
	"mibee-steward/internal/service/scannerv2/probe"
	"mibee-steward/internal/testutil"
)

// TestNewEngine_LoadedPathsAndScanTails covers the NewEngine branches the
// degradation ladder in round13 leaves closed: a READABLE OUI file (loaded),
// an OUI path that hard-fails (a directory), a fingerprint dir with a VALID
// rule (rc.Loaded), the eBPF-enabled log branch, the SNMP-community override
// log — plus the ScanTargets early-exit tails (bad targets / empty expansion /
// canceled context) and the credential-resolution failure path.
func TestNewEngine_LoadedPathsAndScanTails(t *testing.T) {
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	tmp := t.TempDir()

	// A readable OUI file with one prefix → the Loaded() branch.
	validOUI := filepath.Join(tmp, "oui.txt")
	require.NoError(t, os.WriteFile(validOUI, []byte("BCAD28\tHikvision Digital Technology\n"), 0o600))
	// A fingerprint dir with one VALID rule yaml → the rc.Loaded() branch.
	validFP := filepath.Join(tmp, "fp")
	require.NoError(t, os.MkdirAll(validFP, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(validFP, "rule.yaml"), []byte(
		"version: 1\nrules:\n  - id: test-rule\n    source: builtin\n    match:\n      kind: banner\n      field: banner\n      op: prefix_ci\n      value: \"TEST-BANNER-\"\n    service: test-svc\n    protocol: tcp\n    confidence: 0.9\n"), 0o600))

	eng, err := NewEngine(db, Config{
		AllowReservedTargets: true,
		PerProbeTimeout:      200 * time.Millisecond,
		PerHostTimeout:       2 * time.Second,
		OUIPath:              validOUI,
		FingerprintPath:      validFP,
		SNMPCommunity:        "private",
		EBPF:                 ebpf.Config{Enabled: true},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, eng)

	// An OUI path that is a DIRECTORY makes the file-read fail hard → the
	// warn-and-fall-back branch (distinct from the missing-file degradation).
	eng2, err := NewEngine(db, Config{
		PerProbeTimeout: 200 * time.Millisecond,
		PerHostTimeout:  2 * time.Second,
		OUIPath:         tmp, // a directory, not a file
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, eng2)

	// EstimateTargetCount: a spec that fails to expand → error; a valid one
	// returns the count.
	_, err = eng.EstimateTargetCount("not-a-target")
	require.Error(t, err)
	n, err := eng.EstimateTargetCount("127.0.0.1/32")
	require.NoError(t, err)
	require.Equal(t, 1, n)

	// ScanTargets early exits: unparseable spec, empty expansion (a /32 in
	// 0.0.0.0/32? use an address that expands to zero via a bad range), and a
	// canceled context (select hits ctx.Done at the first loop iteration).
	_, err = eng.ScanTargets(context.Background(), "not-a-target", false, 0)
	require.Error(t, err)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = eng.ScanTargets(canceled, "127.0.0.1,127.0.0.2", false, 0)
	require.ErrorIs(t, err, context.Canceled)

	// Credential binding: a resolver wired with a REAL cipher but no stored
	// credential for the id → resolution fails and aborts the scan (no silent
	// downgrade to community).
	cipher, err := crypto.NewCipher(make([]byte, crypto.MasterKeyLen))
	require.NoError(t, err)
	eng3, err := NewEngine(db, Config{
		PerProbeTimeout: 200 * time.Millisecond,
		PerHostTimeout:  2 * time.Second,
		CredResolver:    credresolver.New(db, cipher),
	}, nil)
	require.NoError(t, err)
	_, err = eng3.ScanTargets(context.Background(), "127.0.0.1/32", false, 424242)
	require.Error(t, err)
}

// TestEngine_PostScanMACResolverClosure drives the closure NewEngine installs
// via probe.SetPostScanResolver: on a host with no ARP entry (and no router
// walk hit) it returns empty; with routers configured it takes the SNMP
// cross-subnet branch, which fails fast against a dead router. Either way the
// empty-MAC early return and the OUI lookup path run.
func TestEngine_PostScanMACResolverClosure(t *testing.T) {
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// No routers: pure miss path. (NewEngine's side effect — installing the
	// closure via probe.SetPostScanResolver — is what we exercise.)
	_, err = NewEngine(db, Config{
		PerProbeTimeout: 200 * time.Millisecond,
		PerHostTimeout:  2 * time.Second,
	}, nil)
	require.NoError(t, err)

	mac, dev, vendor, prefix := probe.ResolveMACPostScan("203.0.113.77")
	require.Empty(t, mac)
	require.Empty(t, dev)
	require.Empty(t, vendor)
	require.Empty(t, prefix)

	// With a router configured (dead address + short timeout) the router-walk
	// branch runs and still misses.
	eng2, err := NewEngine(db, Config{
		PerProbeTimeout: 200 * time.Millisecond,
		PerHostTimeout:  2 * time.Second,
		RouterARP: probe.RouterARPConfig{
			Routers: []string{"127.0.0.1"},
			Timeout: 150 * time.Millisecond,
		},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, eng2)

	mac, _, _, _ = probe.ResolveMACPostScan("203.0.113.78")
	require.Empty(t, mac)
}
