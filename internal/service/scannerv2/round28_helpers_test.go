// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package scannerv2

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// failingRepo wraps recordRepo failing the evidence/services writes so Run's
// debug-log tails execute without aborting the scan.
type failingRepo struct{ recordRepo }

func (f *failingRepo) RecordEvidence(context.Context, []Evidence) error { return errRepoFail }
func (f *failingRepo) RecordServices(context.Context, string, []ServiceIdentity, []int) error {
	return errRepoFail
}

var errRepoFail = &repoError{}

type repoError struct{}

func (*repoError) Error() string { return "repo fail" }

// TestOrchestrator_RunToleratesRepoWriteFailures: evidence/service
// persistence failures are debug-logged, never abort the host scan.
func TestOrchestrator_RunToleratesRepoWriteFailures(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterProbe(stubProbe{name: "active:tcp", ev: []Evidence{
		{Kind: "port_open", IP: "10.0.0.3", Port: 80, Protocol: "tcp"},
	}})
	reg.RegisterClassifier(kindClassifier{service: "http", kind: "port_open"})
	reg.RegisterHandler(&stubHandler{service: "http"})

	repo := &failingRepo{recordRepo: *newRecordRepo()}
	orch := NewOrchestrator(reg, repo, OrchestratorConfig{MaxConcurrentHosts: 1}, nil)
	rep := orch.Run(context.Background(), "10.0.0.3", ProbeHint{Timeout: time.Second})
	require.True(t, rep.Alive, "repo write failures must not fail the scan")
	require.NotEmpty(t, rep.Services)
}

// TestOrchestrator_PureHelperTails pins the lookup helpers' remaining arms.
func TestOrchestrator_PureHelperTails(t *testing.T) {
	require.True(t, hasEvidenceKind([]Evidence{{Kind: "mac"}, {Kind: "snmp"}}, "snmp"))
	require.False(t, hasEvidenceKind(nil, "mac"))

	require.Equal(t, []int{1, 2}, closedPortsFromEvidence([]Evidence{
		{Kind: "port_closed", Port: 1}, {Kind: "other", Port: 9}, {Kind: "port_closed", Port: 2},
	}))

	require.Equal(t, "Caddy", httpServerToBrand("caddy/2.7"))
	require.Equal(t, "lighttpd", httpServerToBrand("lighttpd/1.4"))
	require.Empty(t, httpServerToBrand("weird-server"))

	require.Equal(t, "Axis", certCNToBrand("AXIS P3245 Network Camera"))
	require.Equal(t, "QNAP", certCNToBrand("QNAP NAS default"))
	require.Equal(t, "Cisco", certCNToBrand("Cisco Small Business"))
	require.Equal(t, "Fortinet", certCNToBrand("FortiGate-60F"))
	require.Empty(t, certCNToBrand("whatever"))

	require.Empty(t, ssdpServerToOS("unknown-agent"))
	require.Empty(t, ssdpServerToBrand("totally-unknown"))
}
