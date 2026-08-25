// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

func newFingerprintTestService(t *testing.T) *FingerprintReportService {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return NewFingerprintReportService(db.New(conn), conn)
}

func insertCoverageDevice(t *testing.T, svc *FingerprintReportService, ip, uuid, attrs string) {
	t.Helper()
	_, err := svc.dbtx.ExecContext(context.Background(), `INSERT INTO devices (device_uuid, name, ip_address, mac_address, type, status, scan_attributes)
		VALUES (?, ?, ?, ?, ?, 'online', ?)`, uuid, ip, ip, "", "other", attrs)
	require.NoError(t, err)
}

func TestCoverage_TiersAndGrouping(t *testing.T) {
	svc := newFingerprintTestService(t)
	ctx := context.Background()

	insertCoverageDevice(t, svc, "10.0.0.1", "u-prot", `{"inferred_type":"camera","inferred_type_source":"protocol","vendor":"Hikvision"}`)
	insertCoverageDevice(t, svc, "10.0.0.2", "u-heur", `{"inferred_type":"pc","inferred_type_source":"heuristic","hostname":"DESKTOP-ABC"}`)
	insertCoverageDevice(t, svc, "10.0.0.3", "u-un-1", `{"inferred_type":"other","oui_vendor":"TP-Link","hostname":"espresso-01"}`)
	insertCoverageDevice(t, svc, "10.0.0.4", "u-un-2", `{"inferred_type":"other","oui_vendor":"TP-Link","hostname":"espresso-02"}`)
	insertCoverageDevice(t, svc, "10.0.0.5", "u-un-3", `{"inferred_type":"other"}`)

	// services for the port-signature grouping
	_, err := svc.dbtx.ExecContext(ctx, `INSERT INTO host_services (ip, service, port, protocol, confidence, metadata)
		VALUES ('10.0.0.3','http',80,'tcp',0.9,'{}'), ('10.0.0.4','http',80,'tcp',0.9,'{}')`)
	require.NoError(t, err)

	cov, err := svc.Coverage(ctx, domain.Scope{Global: true})
	require.NoError(t, err)
	require.EqualValues(t, 5, cov.Total)
	require.EqualValues(t, 1, cov.Protocol)
	require.EqualValues(t, 1, cov.Heuristic)
	require.EqualValues(t, 3, cov.Unidentified)
	require.Len(t, cov.Devices, 3)

	// groups: oui TP-Link x2, ports 80 x2, hostname espresso x2 — all tied
	// at count 2, so assert by KIND lookup, not positional order (the sort
	// tiebreaks deterministically on kind/signature, but no kind is "first"
	// among equals).
	require.NotEmpty(t, cov.Groups)
	var ouiGroup *UnidentifiedGroup
	for i := range cov.Groups {
		if cov.Groups[i].Kind == "oui" {
			ouiGroup = &cov.Groups[i]
		}
	}
	require.NotNil(t, ouiGroup, "oui group expected")
	require.Equal(t, "TP-Link", ouiGroup.Signature)
	require.EqualValues(t, 2, ouiGroup.Count)

	var portsGroup *UnidentifiedGroup
	for i := range cov.Groups {
		if cov.Groups[i].Kind == "ports" {
			portsGroup = &cov.Groups[i]
		}
	}
	require.NotNil(t, portsGroup, "port-signature group expected")
	require.Equal(t, "80", portsGroup.Signature)

	// services attached to the device rows
	for _, d := range cov.Devices {
		if d.IP == "10.0.0.3" {
			require.Equal(t, []int{80}, d.Ports)
			require.Equal(t, []string{"http"}, d.Services)
		}
	}
}

func TestCoverage_RestrictedScopeFilters(t *testing.T) {
	svc := newFingerprintTestService(t)
	ctx := context.Background()

	// net 1: one unidentified; net 2: one protocol-identified
	_, err := svc.dbtx.ExecContext(ctx, `INSERT INTO networks (name, cidr) VALUES ('n1', '10.1.0.0/24')`)
	require.NoError(t, err)
	insertCoverageDevice(t, svc, "10.1.0.9", "u-n1", `{"inferred_type":"other"}`)
	_, err = svc.dbtx.ExecContext(ctx, `UPDATE devices SET network_id = 1 WHERE device_uuid = 'u-n1'`)
	require.NoError(t, err)
	insertCoverageDevice(t, svc, "10.2.0.9", "u-n2", `{"inferred_type":"nas","inferred_type_source":"protocol"}`)
	_, err = svc.dbtx.ExecContext(ctx, `UPDATE devices SET network_id = 2 WHERE device_uuid = 'u-n2'`)
	require.NoError(t, err)

	cov, err := svc.Coverage(ctx, domain.Scope{Global: false, NetworkIDs: []int64{1}})
	require.NoError(t, err)
	require.EqualValues(t, 1, cov.Total)
	require.EqualValues(t, 1, cov.Unidentified)
	require.Len(t, cov.Devices, 1)
	require.Equal(t, "10.1.0.9", cov.Devices[0].IP)
}

func TestRuleDraft_GeneratesAndValidates(t *testing.T) {
	svc := newFingerprintTestService(t)
	ctx := context.Background()

	insertCoverageDevice(t, svc, "10.0.0.50", "u-draft", `{"inferred_type":"other"}`)
	_, err := svc.dbtx.ExecContext(ctx, `INSERT INTO service_evidence (ip, device_uuid, source, kind, port, protocol, raw_data, confidence)
		VALUES
		 ('10.0.0.50','u-draft','active:snmp','snmp',161,'udp','{"sys_descr":"RX3040 Revolution Router OS 1.2"}',0.9),
		 ('10.0.0.50','u-draft','active:tcp','banner',9999,'tcp','{"banner":"ACME-DVR greet v2"}',0.8)`)
	require.NoError(t, err)

	draft, err := svc.RuleDraft(ctx, "u-draft", domain.Scope{Global: true})
	require.NoError(t, err)
	require.Contains(t, draft, "sys_descr")
	require.Contains(t, draft, "RX3040 Revolution Router") // significant token survives
	require.Contains(t, draft, "ACME-DVR greet v2")
	require.Contains(t, draft, "version: 1")
	// generated rules carry TODO service where no port hint exists
	require.Contains(t, draft, "TODO")

	// The draft is validated inside RuleDraft (fp.LoadFromDir compile); reaching
	// here without error means the YAML parses AND compiles.
}

func TestRuleDraft_NoEvidenceReturnsHeader(t *testing.T) {
	svc := newFingerprintTestService(t)
	ctx := context.Background()
	insertCoverageDevice(t, svc, "10.0.0.51", "u-empty", `{"inferred_type":"other"}`)

	draft, err := svc.RuleDraft(ctx, "u-empty", domain.Scope{Global: true})
	require.NoError(t, err)
	require.Contains(t, draft, "No banner / HTTP / SNMP / RTSP evidence")
}

func TestRuleDraft_OutOfScopeRejected(t *testing.T) {
	svc := newFingerprintTestService(t)
	ctx := context.Background()

	_, err := svc.dbtx.ExecContext(ctx, `INSERT INTO networks (name, cidr) VALUES ('n1', '10.1.0.0/24')`)
	require.NoError(t, err)
	insertCoverageDevice(t, svc, "10.1.0.9", "u-scoped", `{"inferred_type":"other"}`)
	_, err = svc.dbtx.ExecContext(ctx, `UPDATE devices SET network_id = 1 WHERE device_uuid = 'u-scoped'`)
	require.NoError(t, err)

	_, err = svc.RuleDraft(ctx, "u-scoped", domain.Scope{Global: false, NetworkIDs: []int64{99}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "scope")
}
