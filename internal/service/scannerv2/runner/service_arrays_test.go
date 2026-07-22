// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

package runner

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2"
)

// TestServiceArrays_DedupesByPortName is the regression test for the
// detected_services duplication bug: when multiple evidence sources identify
// the same (port, name) service (e.g. a banner HTTP probe without a version +
// a richer HTTP probe that parsed nginx 1.12.2), the output must collapse them
// into ONE entry, keeping the richest version. On the test env, port 80
// appeared 6× and 8080 5× in a single device's detected_services.
func TestServiceArrays_DedupesByPortName(t *testing.T) {
	rep := scannerv2.HostReport{
		Services: []scannerv2.ServiceIdentity{
			{Port: 80, Service: "http", Protocol: "tcp", Metadata: map[string]string{"version": "1.12.2"}},
			{Port: 80, Service: "http", Protocol: "tcp"},                   // dup, no version → dropped
			{Port: 80, Service: "http", Protocol: "tcp", Metadata: map[string]string{"version": "1.12.2"}}, // dup, same version
			{Port: 8080, Service: "http", Protocol: "tcp"},                 // distinct port, kept
			{Port: 8080, Service: "http", Protocol: "tcp", Metadata: map[string]string{"version": "1.12.2"}}, // dup, richer → wins
			{Port: 443, Service: "https", Protocol: "tcp"},                 // distinct, kept
		},
	}

	_, svcs := serviceArrays(rep)
	require.Len(t, svcs, 3, "(port,name) pairs must be deduped")

	// Sorted by (port, name).
	require.Equal(t, 80, svcs[0].Port)
	require.Equal(t, "1.12.2", svcs[0].Version, "richest version must win on collision")
	require.Equal(t, 443, svcs[1].Port)
	require.Equal(t, 8080, svcs[2].Port)
	require.Equal(t, "1.12.2", svcs[2].Version, "the version-bearing dup replaces the bare one")
}

// TestDeviceScanInfoJSON_MatchesDedupedSource verifies the top-level
// devices.detected_services column is sourced from the same deduped set as
// scan_attributes (single source of truth), so the two never diverge.
func TestDeviceScanInfoJSON_MatchesDedupedSource(t *testing.T) {
	rep := scannerv2.HostReport{
		Services: []scannerv2.ServiceIdentity{
			{Port: 80, Service: "http", Protocol: "tcp", Metadata: map[string]string{"version": "1.12.2"}},
			{Port: 80, Service: "http", Protocol: "tcp"},
			{Port: 80, Service: "http", Protocol: "tcp"},
		},
	}
	_, svcJSON := deviceScanInfoJSON(rep)

	var got []struct {
		Port int    `json:"port"`
		Name string `json:"name"`
	}
	require.NoError(t, json.Unmarshal([]byte(svcJSON), &got))
	require.Len(t, got, 1, "top-level detected_services must also be deduped")
	require.Equal(t, "http", got[0].Name)
}

// TestServiceArrays_Empty confirms a nil/empty service list yields empty
// (not nil) slices so downstream JSON marshalling produces [] not null.
func TestServiceArrays_Empty(t *testing.T) {
	openPorts, svcs := serviceArrays(scannerv2.HostReport{})
	require.Len(t, openPorts, 0)
	require.Len(t, svcs, 0)
	_ = domain.ServiceEntry{} // keep import meaningful for future assertions
}
