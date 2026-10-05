// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of Mi Bee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text.
// A commercial license is available for use cases the AGPL does not accommodate.

package probe

import (
	"testing"

	"mibee-steward/internal/service/scannerv2"
)

// TestTLSCertCNFeedsHostnameRules pins the 2026-10-06 field finding: a router
// signs its model into the TLS cert CN ("R68S"), and the orchestrator's
// host-fact fold treats the CN as a node_hostname FALLBACK — but the fold runs
// after classification, so the corpus's hostname rules (kind "hostname") never
// saw it and the device stayed model-less although the rule matched. The TLS
// probe now also emits a hostname-kind evidence piece when the leaf CN looks
// like a device hostname (single DNS label), mirroring the NBNS fix.
func TestTLSCertCNFeedsHostnameRules(t *testing.T) {
	leaf := scannerv2.TLSCertRecord{SubjectCN: "R68S"}
	evs := tlsEvidenceWithCertCN("192.0.2.1", 443, leaf)
	var tlsPieces, hostPieces int
	var hostname string
	for _, ev := range evs {
		switch ev.Kind {
		case "tls":
			tlsPieces++
		case "hostname":
			hostPieces++
			hostname = ev.RawData["hostname"]
		}
	}
	if tlsPieces != 1 || hostPieces != 1 {
		t.Fatalf("pieces: tls=%d hostname=%d, want 1/1", tlsPieces, hostPieces)
	}
	if hostname != "R68S" {
		t.Errorf("hostname piece = %q, want R68S", hostname)
	}

	// Certificate-ish CNs must NOT synthesize hostname evidence ("root" DOES
	// pass the shape gate — no vendor rule matches it and the orchestrator
	// fold already uses it as the node_hostname fallback today, so synthesizing
	// changes nothing; only dotted/spaced/wildcard labels are excluded).
	for _, cn := range []string{"MIWIFI SERVER CERT", "*.hikvision.com", ""} {
		evs := tlsEvidenceWithCertCN("192.0.2.1", 443, scannerv2.TLSCertRecord{SubjectCN: cn})
		for _, ev := range evs {
			if ev.Kind == "hostname" {
				t.Errorf("CN %q synthesized a hostname piece", cn)
			}
		}
		if cn == "" && len(evs) != 1 {
			t.Errorf("empty CN: %d pieces, want only the tls piece", len(evs))
		}
	}
}
