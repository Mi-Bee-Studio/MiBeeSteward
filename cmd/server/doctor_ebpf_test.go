// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package main

import (
	"strings"
	"testing"

	scannerv2ebpf "mibee-steward/internal/service/scannerv2/ebpf"
)

// ebpfDoctorCheck maps a prerequisite evaluation onto doctor outcomes (#495).
// It consumes ebpf.PrereqStatus values directly, so every case is testable on
// the default build (stub) without a kernel.

func TestEbpfDoctorCheck(t *testing.T) {
	cases := []struct {
		name     string
		ps       scannerv2ebpf.PrereqStatus
		want     string
		wantHint string
	}{
		{"healthy host", scannerv2ebpf.PrereqStatus{Kernel: "6.6.144", BTF: true},
			"ok", ""},
		{"healthy host without BTF", scannerv2ebpf.PrereqStatus{Kernel: "6.6.144", BTF: false,
			Warnings: []string{"kernel BTF not found (/sys/kernel/btf/vmlinux); the TC program is CO-RE free so loading may still work"}},
			"warn", "CO-RE"},
		{"missing caps", scannerv2ebpf.PrereqStatus{Kernel: "6.6.144", BTF: true,
			CapsMissing: []string{"CAP_NET_ADMIN", "CAP_BPF"},
			Unsupported: []string{"missing privileges: CAP_NET_ADMIN, CAP_BPF (run as root, or grant ambient caps — see docs/en/ebpf.md)"}},
			"fail", "drop-in"},
		{"old kernel", scannerv2ebpf.PrereqStatus{Kernel: "5.15.0", BTF: true,
			Unsupported: []string{"kernel 5.15.0 is older than 6.6 (the TCX attach era); upgrade the kernel to use the passive observer"}},
			"fail", "docs/en/ebpf.md"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ebpfDoctorCheck(c.ps)
			if got.status != c.want {
				t.Fatalf("status = %q, want %q", got.status, c.want)
			}
			if c.wantHint != "" && !strings.Contains(got.fixHint, c.wantHint) {
				t.Fatalf("fixHint = %q, want it to contain %q", got.fixHint, c.wantHint)
			}
			if c.want == "ok" && !strings.Contains(got.detail, "kernel="+c.ps.Kernel) {
				t.Fatalf("detail = %q, want kernel mention", got.detail)
			}
		})
	}
}
