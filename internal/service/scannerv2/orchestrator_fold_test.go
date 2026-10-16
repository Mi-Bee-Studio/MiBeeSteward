// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package scannerv2

import (
	"context"
	"testing"
	"time"
)

// TestOrchestrator_DispatchEvidenceFold drives the host-level evidence fold
// (mac/hostname/tls/http/mdns/ssdp) with one probe per scenario, asserting the
// DeviceRef.Fields each fold writes. Uses the existing stub harness.
func TestOrchestrator_DispatchEvidenceFold(t *testing.T) {
	run := func(evs ...Evidence) HostReport {
		repo := newRecordRepo()
		reg := NewRegistry()
		reg.RegisterProbe(stubProbe{name: "active:fold", ev: evs})
		orch := NewOrchestrator(reg, repo, OrchestratorConfig{MaxConcurrentHosts: 1}, nil)
		return orch.Run(context.Background(), "10.200.0.1", ProbeHint{Timeout: time.Second})
	}

	// mac + OUI: fills mac/brand/oui fields.
	rep := run(Evidence{Kind: "mac", RawData: map[string]string{
		"mac": "aa:bb:cc:00:11:22", "vendor": "acme", "oui_prefix": "AABBCC", "oui_vendor": "Acme Silicon",
	}})
	if rep.Device.Fields["mac"] != "aa:bb:cc:00:11:22" || rep.Device.Fields["inferred_brand"] != "acme" ||
		rep.Device.Fields["oui_prefix"] != "AABBCC" || rep.Device.Fields["oui_vendor"] != "Acme Silicon" {
		t.Fatalf("mac fold wrong: %v", rep.Device.Fields)
	}

	// hostname (rDNS) → node_hostname.
	rep = run(Evidence{Kind: "hostname", RawData: map[string]string{"hostname": "core.lan"}})
	if rep.Device.Fields["node_hostname"] != "core.lan" {
		t.Fatalf("hostname fold wrong: %v", rep.Device.Fields)
	}

	// Garbage hostnames never land: a mojibake name (invalid UTF-8 with a
	// control byte, as a broken NBNS/mDNS parser can emit — field-found
	// 2026-10-15: a rig device displayed a binary-garbage hostname) must be
	// dropped, while a CJK marketing suffix (TL-XDR易展版) stays.
	rep = run(Evidence{Kind: "hostname", RawData: map[string]string{"hostname": "L\x14ÿ.lan"}})
	if _, ok := rep.Device.Fields["node_hostname"]; ok {
		t.Fatalf("garbage hostname must be dropped, got %q", rep.Device.Fields["node_hostname"])
	}
	rep = run(Evidence{Kind: "hostname", RawData: map[string]string{"hostname": "TL-XDR3040易展版"}})
	if rep.Device.Fields["node_hostname"] != "TL-XDR3040易展版" {
		t.Fatalf("CJK hostname must survive the gate: %q", rep.Device.Fields["node_hostname"])
	}

	// The gate covers every node_hostname entry point, not just the hostname
	// evidence kind: broken NBNS/mDNS decoders emit their mojibake through
	// the mdns and netbios folds too, and a garbage TLS-CN is equally
	// possible from a malformed cert.
	for _, kind := range []string{"mdns", "netbios"} {
		rep = run(Evidence{Kind: kind, RawData: map[string]string{"hostname": "L\x14ÿ.lan"}})
		if _, ok := rep.Device.Fields["node_hostname"]; ok {
			t.Fatalf("%s garbage hostname must be dropped, got %q", kind, rep.Device.Fields["node_hostname"])
		}
	}
	rep = run(Evidence{Kind: "netbios", RawData: map[string]string{"hostname": "TL-XDR3040易展版", "workgroup": "WORKGROUP"}})
	if rep.Device.Fields["node_hostname"] != "TL-XDR3040易展版" {
		t.Fatalf("CJK netbios hostname must survive the gate: %q", rep.Device.Fields["node_hostname"])
	}
	if rep.Device.Fields["netbios_workgroup"] != "WORKGROUP" {
		t.Fatalf("ungated sibling field unaffected: %v", rep.Device.Fields)
	}

	// TLS: wildcard CN fills hostname; cert brand overrides a generic
	// web-server brand.
	rep = run(
		Evidence{Kind: "http", RawData: map[string]string{"server": "nginx/1.24"}},
		Evidence{Kind: "tls", RawData: map[string]string{"subject_cn": "*.hikvision.com", "issuer_org": ""}},
	)
	if rep.Device.Fields["inferred_brand"] != "Hikvision" {
		t.Fatalf("tls brand must override generic web-server brand: %v", rep.Device.Fields)
	}
	if rep.Device.Fields["node_hostname"] != "hikvision.com" {
		t.Fatalf("wildcard CN must become hostname: %v", rep.Device.Fields)
	}

	// http alone (no camera evidence): Server header → web-server brand.
	rep = run(Evidence{Kind: "http", RawData: map[string]string{"server": "Apache/2.4"}})
	if rep.Device.Fields["inferred_brand"] != "Apache" {
		t.Fatalf("http brand fold wrong: %v", rep.Device.Fields)
	}

	// http WITH camera evidence: the web-server brand is suppressed.
	rep = run(
		Evidence{Kind: "rtsp_banner", RawData: map[string]string{"server": "nginx"}},
		Evidence{Kind: "http", RawData: map[string]string{"server": "nginx"}},
	)
	if rep.Device.Fields["inferred_brand"] == "nginx" {
		t.Fatalf("camera host must not take the reverse-proxy brand: %v", rep.Device.Fields)
	}

	// mDNS: hostname + txt.vendor brand.
	rep = run(Evidence{Kind: "mdns", RawData: map[string]string{
		"hostname": "cam-2.lan", "txt.vendor": "Hikvision", "txt.md": "DS-2CD",
	}})
	if rep.Device.Fields["node_hostname"] != "cam-2.lan" || rep.Device.Fields["inferred_brand"] != "Hikvision" {
		t.Fatalf("mdns fold wrong: %v", rep.Device.Fields)
	}

	// ssdp: OS + product brand from the SERVER header.
	rep = run(Evidence{Kind: "ssdp", RawData: map[string]string{"server": "Linux/4.4 UPnP/1.1 Sonos/70.4"}})
	if rep.Device.Fields["os_type"] == "" && rep.Device.Fields["inferred_brand"] == "" {
		t.Fatalf("ssdp fold produced nothing: %v", rep.Device.Fields)
	}
}
