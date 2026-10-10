// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package ebpf

import (
	"context"
	"strings"
	"testing"

	"mibee-steward/internal/service/scannerv2"
)

// These tests run on the DEFAULT build (stub): they pin the no-op contract
// and the Status surface doctor relies on (#493).

func TestStubBuiltWithEBPF(t *testing.T) {
	if BuiltWithEBPF() {
		t.Fatal("default build must report BuiltWithEBPF()==false")
	}
}

func TestStubStatus(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		st := New(Config{Enabled: false}).Status()
		if st.State != StateDisabled || !strings.Contains(st.Reason, "enabled is false") {
			t.Fatalf("Status = %+v, want disabled", st)
		}
	})

	t.Run("enabled but not built", func(t *testing.T) {
		st := New(Config{Enabled: true, Interfaces: []string{"eth0"}}).Status()
		if st.State != StateNotBuilt || !strings.Contains(st.Reason, "WITH_EBPF") {
			t.Fatalf("Status = %+v, want not-built with WITH_EBPF hint", st)
		}
	})
}

func TestStubProbeNeverErrors(t *testing.T) {
	o := New(Config{Enabled: true})
	for _, ip := range []string{"192.0.2.1", ""} {
		ev, err := o.Probe(context.Background(), ip, scannerv2.ProbeHint{})
		if err != nil || ev != nil {
			t.Fatalf("stub Probe(%q) = %v, %v; want nil, nil", ip, ev, err)
		}
	}
}

func TestObserverName(t *testing.T) {
	if got := New(Config{}).Name(); got != "passive:ebpf:tc" {
		t.Fatalf("Name = %q", got)
	}
}
