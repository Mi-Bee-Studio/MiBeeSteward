// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package main

import (
	"strings"
	"testing"

	"mibee-steward/internal/config"
)

// optionalSourceDoctorCheck maps the frame/ARP capability triad (#502) onto
// doctor outcomes. Inputs are plain values so every branch is testable on the
// default build and on any OS.

func TestFrameListenerDoctorCheck(t *testing.T) {
	cases := []struct {
		name     string
		goos     string
		built    bool
		capRaw   bool
		want     string
		wantHint string
	}{
		{"not linux", "windows", true, true, "skip", ""},
		{"default build", "linux", false, false, "skip", "WITH_LLDP"},
		{"built with cap", "linux", true, true, "ok", ""},
		{"built without cap", "linux", true, false, "warn", "CAP_NET_RAW"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := frameListenerDoctorCheck("lldp listener", "WITH_LLDP", c.goos, c.built, c.capRaw)
			if got.status != c.want {
				t.Fatalf("status = %q, want %q (detail=%q)", got.status, c.want, got.detail)
			}
			if c.wantHint != "" && !strings.Contains(got.detail+got.fixHint, c.wantHint) {
				t.Fatalf("detail/hint = %q/%q, want mention of %q", got.detail, got.fixHint, c.wantHint)
			}
		})
	}
}

func TestArpScanDoctorCheck(t *testing.T) {
	cases := []struct {
		name     string
		goos     string
		enabled  bool
		built    bool
		capRaw   bool
		want     string
		contains string
	}{
		{"not linux", "windows", true, true, true, "skip", ""},
		{"disabled in config", "linux", false, false, false, "skip", "arp_scan.enabled is false"},
		{"enabled but default build", "linux", true, false, false, "warn", "WITH_ARPSCAN"},
		{"enabled built with cap", "linux", true, true, true, "ok", "CAP_NET_RAW"},
		{"enabled built without cap", "linux", true, true, false, "warn", "CAP_NET_RAW"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Scanner.Discovery.ARPScan.Enabled = c.enabled
			got := arpScanDoctorCheck(cfg, c.goos, c.built, c.capRaw)
			if got.status != c.want {
				t.Fatalf("status = %q, want %q (detail=%q)", got.status, c.want, got.detail)
			}
			if c.contains != "" && !strings.Contains(got.detail+got.fixHint, c.contains) {
				t.Fatalf("detail/hint = %q/%q, want mention of %q", got.detail, got.fixHint, c.contains)
			}
		})
	}
}
