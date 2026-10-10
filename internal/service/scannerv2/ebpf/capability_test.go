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
	"strings"
	"testing"
)

func TestParseKernelRelease(t *testing.T) {
	cases := []struct {
		in           string
		major, minor int
		ok           bool
	}{
		{"6.6.144", 6, 6, true},
		{"5.15.0-rc7", 5, 15, true},
		{"6.18.40.1-microsoft-standard", 6, 18, true},
		{"4.19", 4, 19, true},
		{"", 0, 0, false},
		{"6", 0, 0, false},
		{"x.y.z", 0, 0, false},
		{"6.x.1", 0, 0, false},
	}
	for _, c := range cases {
		major, minor, ok := parseKernelRelease(c.in)
		if ok != c.ok || major != c.major || minor != c.minor {
			t.Errorf("parseKernelRelease(%q) = (%d,%d,%v), want (%d,%d,%v)",
				c.in, major, minor, ok, c.major, c.minor, c.ok)
		}
	}
}

func TestParseCapEff(t *testing.T) {
	const status = "Name:\tmibee\nUid:\t1000\t1000\t1000\t5\nCapEff:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\n"
	if got := parseCapEff(status); got != 0x1ffffffffff {
		t.Errorf("parseCapEff = %#x, want %#x", got, uint64(0x1ffffffffff))
	}
	if got := parseCapEff("Name:\tx\n"); got != 0 {
		t.Errorf("parseCapEff(missing) = %#x, want 0", got)
	}
	if got := parseCapEff("CapEff:\tnothex\n"); got != 0 {
		t.Errorf("parseCapEff(garbage) = %#x, want 0", got)
	}
}

func TestParseStatusUIDField(t *testing.T) {
	const status = "Uid:\t1000\t0\t1000\t5\n"
	if got := parseStatusUIDField(status, "Uid:"); got != 0 {
		t.Errorf("effective uid = %d, want 0 (second field)", got)
	}
	if got := parseStatusUIDField("Gid:\t5\t5\t5\t5\n", "Uid:"); got != -1 {
		t.Errorf("missing key = %d, want -1", got)
	}
	if got := parseStatusUIDField("Uid:\tbroken\n", "Uid:"); got != -1 {
		t.Errorf("unparsable = %d, want -1", got)
	}
}

func TestEvaluatePrereqs(t *testing.T) {
	t.Run("non-linux is unsupported", func(t *testing.T) {
		ev := evaluatePrereqs(probeResult{goos: "windows"})
		if len(ev.Unsupported) != 1 || !strings.Contains(ev.Unsupported[0], "Linux") {
			t.Fatalf("Unsupported = %v, want one Linux message", ev.Unsupported)
		}
	})

	t.Run("kernel below 6.6 is unsupported", func(t *testing.T) {
		ev := evaluatePrereqs(probeResult{goos: "linux", release: "5.15.0-rc8", euid: 0, btf: true})
		if len(ev.Unsupported) != 1 || !strings.Contains(ev.Unsupported[0], "older than 6.6") {
			t.Fatalf("Unsupported = %v, want kernel-too-old", ev.Unsupported)
		}
	})

	t.Run("kernel 6.6 exactly passes", func(t *testing.T) {
		ev := evaluatePrereqs(probeResult{goos: "linux", release: "6.6.0", euid: 0, btf: true})
		if len(ev.Unsupported) != 0 {
			t.Fatalf("Unsupported = %v, want empty", ev.Unsupported)
		}
	})

	t.Run("unparsable release warns but proceeds", func(t *testing.T) {
		ev := evaluatePrereqs(probeResult{goos: "linux", release: "weird-kernel", euid: 0, btf: true})
		if len(ev.Unsupported) != 0 || len(ev.Warnings) != 1 || !strings.Contains(ev.Warnings[0], "unparsable") {
			t.Fatalf("got Unsupported=%v Warnings=%v", ev.Unsupported, ev.Warnings)
		}
	})

	t.Run("unprivileged without caps is unsupported with named caps", func(t *testing.T) {
		ev := evaluatePrereqs(probeResult{goos: "linux", release: "6.6.0", euid: 1000, capEff: 0, btf: true})
		if len(ev.Unsupported) != 1 || !strings.Contains(ev.Unsupported[0], "missing privileges") {
			t.Fatalf("Unsupported = %v, want missing privileges", ev.Unsupported)
		}
		want := []string{"CAP_NET_ADMIN", "CAP_BPF"}
		if len(ev.MissingCaps) != len(want) {
			t.Fatalf("MissingCaps = %v, want %v", ev.MissingCaps, want)
		}
		for i, n := range want {
			if ev.MissingCaps[i] != n {
				t.Errorf("MissingCaps[%d] = %s, want %s (deterministic order)", i, ev.MissingCaps[i], n)
			}
		}
	})

	t.Run("partial caps name exactly the missing one", func(t *testing.T) {
		ev := evaluatePrereqs(probeResult{goos: "linux", release: "6.6.0", euid: 1000, capEff: 1 << capNetAdmin, btf: true})
		if len(ev.MissingCaps) != 1 || ev.MissingCaps[0] != "CAP_BPF" {
			t.Fatalf("MissingCaps = %v, want [CAP_BPF]", ev.MissingCaps)
		}
	})

	t.Run("root ignores CapEff", func(t *testing.T) {
		ev := evaluatePrereqs(probeResult{goos: "linux", release: "6.6.0", euid: 0, capEff: 0, btf: true})
		if len(ev.Unsupported) != 0 || len(ev.MissingCaps) != 0 {
			t.Fatalf("Unsupported=%v MissingCaps=%v, want empty", ev.Unsupported, ev.MissingCaps)
		}
	})

	t.Run("missing BTF warns but proceeds", func(t *testing.T) {
		ev := evaluatePrereqs(probeResult{goos: "linux", release: "6.6.0", euid: 0, btf: false})
		if len(ev.Unsupported) != 0 || len(ev.Warnings) != 1 || !strings.Contains(ev.Warnings[0], "BTF") {
			t.Fatalf("Unsupported=%v Warnings=%v", ev.Unsupported, ev.Warnings)
		}
	})
}

func TestProbeSourceRun(t *testing.T) {
	t.Run("linux facts are gathered", func(t *testing.T) {
		s := probeSource{
			goos:       func() string { return "linux" },
			osRelease:  func() ([]byte, error) { return []byte("6.6.144\n"), nil },
			procStatus: func() ([]byte, error) { return []byte("Uid:\t1000\t1000\t1000\t5\nCapEff:\t000001ffffffffff\n"), nil },
			btfPresent: func() bool { return true },
		}
		r := s.run()
		if r.release != "6.6.144" || r.euid != 1000 || !r.btf || r.capEff != 0x1ffffffffff {
			t.Fatalf("run() = %+v", r)
		}
		ev := evaluatePrereqs(r)
		if len(ev.Unsupported) != 0 {
			t.Fatalf("healthy rig reported unsupported: %v", ev.Unsupported)
		}
	})

	t.Run("non-linux never panics and is unsupported", func(t *testing.T) {
		s := probeSource{goos: func() string { return "darwin" }}
		r := s.run()
		if r.readErr == nil {
			t.Fatal("non-linux run must record readErr")
		}
		if ev := evaluatePrereqs(r); len(ev.Unsupported) == 0 {
			t.Fatal("non-linux must evaluate unsupported")
		}
	})

	t.Run("unreadable proc degrades to warnings on linux", func(t *testing.T) {
		s := probeSource{
			goos:       func() string { return "linux" },
			osRelease:  func() ([]byte, error) { return nil, errTest },
			procStatus: func() ([]byte, error) { return nil, errTest },
			btfPresent: func() bool { return false },
		}
		ev := evaluatePrereqs(s.run())
		if len(ev.Unsupported) != 0 {
			t.Fatalf("unreadable /proc must not hard-block on linux, got %v", ev.Unsupported)
		}
	})
}

var errTest = &testError{}

type testError struct{}

func (*testError) Error() string { return "test read failure" }
