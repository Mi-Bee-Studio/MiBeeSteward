// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Capability probing and prerequisite evaluation for the eBPF passive
// observer (#493). This file carries NO build tag so the default build (and
// therefore CI) unit-tests the full decision logic; observer_real.go only
// consumes the verdict. The red line: every eBPF problem degrades the
// observer, it never crashes the server and never blocks active scanning.

package ebpf

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// State is the observer lifecycle state. Every state other than active or
// degraded means the observer contributes no evidence — a pure degradation,
// by design (#493).
type State string

const (
	// StatePending: enabled, but the lazy start has not run yet (the
	// observer starts on the first Probe call from the orchestrator).
	StatePending State = "pending"
	// StateDisabled: turned off by configuration.
	StateDisabled State = "disabled"
	// StateNotBuilt: the binary lacks the WITH_EBPF build tag (stub build).
	StateNotBuilt State = "not-built"
	// StateUnsupported: prerequisites are missing (platform, kernel version,
	// capabilities); the observer does not even attempt to load.
	StateUnsupported State = "unsupported"
	// StateDegraded: running with reduced capability (partial interface
	// attach, or the ring-buffer reader tripped its error breaker).
	StateDegraded State = "degraded"
	// StateActive: fully operational.
	StateActive State = "active"
	// StateFailed: a start attempt was made and failed; the observer stays
	// inactive for the rest of the process lifetime. Active probing is
	// unaffected.
	StateFailed State = "failed"
)

// Status is a point-in-time snapshot of the observer lifecycle, surfaced in
// doctor output and startup logs. It never contains secrets.
type Status struct {
	State State
	// Reason explains why the observer is not StateActive (empty when it is).
	Reason string
	// Kernel is the reported kernel release, when known.
	Kernel string
	// BTF reports whether /sys/kernel/btf/vmlinux exists. The TC program is
	// CO-RE free (bpf/bpf_standalone.h), so BTF is optional: its absence is a
	// warning, not a blocker.
	BTF bool
	// CapsMissing names the capabilities missing when running unprivileged.
	CapsMissing []string
	// InterfacesConfigured is the attach target list (configured, or the
	// auto-detected non-loopback default). InterfacesAttached is the subset
	// the TC program is actually live on.
	InterfacesConfigured []string
	InterfacesAttached   []string
}

// ---------------------------------------------------------------------------
// Platform probe (all reads injectable for tests)
// ---------------------------------------------------------------------------

const (
	capNetAdmin = 12 // CAP_NET_ADMIN
	capBPF      = 39 // CAP_BPF (kernel 5.8+)

	minKernelMajor = 6
	minKernelMinor = 6 // TCX attach (the loader's only TC path on cilium/ebpf v0.22) needs 6.6
)

// requiredCaps is checked in order so reported lists are deterministic.
var requiredCaps = []struct {
	bit  int
	name string
}{
	{capNetAdmin, "CAP_NET_ADMIN"},
	{capBPF, "CAP_BPF"},
}

// btfPath is the kernel BTF blob. Its absence only warns: the TC program is
// CO-RE free and may still load on BTF-less kernels.
const btfPath = "/sys/kernel/btf/vmlinux"

// probeResult is what the platform probe gathered.
type probeResult struct {
	goos    string
	release string // /proc/sys/kernel/osrelease, e.g. "6.6.144"
	btf     bool
	capEff  uint64
	euid    int
	readErr error // set when /proc cannot be read (non-Linux, hardened hosts)
}

// probeSource carries the injectable readers.
type probeSource struct {
	goos       func() string
	osRelease  func() ([]byte, error)
	procStatus func() ([]byte, error)
	btfPresent func() bool
}

// defaultProbeSource reads the real host. It is consumed by the WITH_EBPF
// build (observer_real.go start); the stub build only exercises it in tests.
//
//nolint:unused // used by observer_real.go (WITH_EBPF build); tests use it on the default build
func defaultProbeSource() probeSource {
	return probeSource{
		goos: func() string { return runtime.GOOS },
		osRelease: func() ([]byte, error) {
			return os.ReadFile("/proc/sys/kernel/osrelease")
		},
		procStatus: func() ([]byte, error) {
			return os.ReadFile("/proc/self/status")
		},
		btfPresent: func() bool {
			_, err := os.Stat(btfPath)
			return err == nil
		},
	}
}

// run gathers the platform facts. It never fails: unreadable sources are
// recorded in readErr and the evaluation decides how much that blocks.
func (s probeSource) run() probeResult {
	r := probeResult{goos: s.goos(), euid: -1}
	if s.goos() != "linux" {
		r.readErr = fmt.Errorf("eBPF requires Linux (host is %s)", s.goos())
		return r
	}
	if b, err := s.osRelease(); err == nil {
		r.release = strings.TrimSpace(string(b))
	}
	if b, err := s.procStatus(); err == nil {
		r.capEff = parseCapEff(string(b))
		if v := parseStatusUIDField(string(b), "Uid:"); v >= 0 {
			r.euid = v
		}
	}
	r.btf = s.btfPresent()
	return r
}

// ---------------------------------------------------------------------------
// Evaluation (pure, unit-tested)
// ---------------------------------------------------------------------------

// prereqEval is the verdict of the prerequisite check. Unsupported entries
// are hard blockers (do not attempt to load); Warnings are proceed-anyway
// notes for the operator.
type prereqEval struct {
	Unsupported []string
	Warnings    []string
	MissingCaps []string
}

func evaluatePrereqs(r probeResult) prereqEval {
	var ev prereqEval
	if r.goos != "linux" {
		if r.readErr != nil {
			ev.Unsupported = append(ev.Unsupported, r.readErr.Error())
		} else {
			ev.Unsupported = append(ev.Unsupported, "eBPF requires Linux (host is "+r.goos+")")
		}
		return ev
	}
	major, minor, ok := parseKernelRelease(r.release)
	switch {
	case !ok:
		ev.Warnings = append(ev.Warnings,
			fmt.Sprintf("kernel release %q unparsable; attempting to load anyway", r.release))
	case major < minKernelMajor || (major == minKernelMajor && minor < minKernelMinor):
		ev.Unsupported = append(ev.Unsupported, fmt.Sprintf(
			"kernel %s is older than %d.%d (the TCX attach era); upgrade the kernel to use the passive observer",
			r.release, minKernelMajor, minKernelMinor))
	}
	if r.euid == -1 {
		ev.Warnings = append(ev.Warnings, "cannot determine euid/capabilities from /proc/self/status; attempting to load anyway")
	} else if r.euid != 0 {
		ev.MissingCaps = missingCaps(r.capEff)
		if len(ev.MissingCaps) > 0 {
			ev.Unsupported = append(ev.Unsupported, fmt.Sprintf(
				"missing privileges: %s (run as root, or grant ambient caps — see docs/en/ebpf.md)",
				strings.Join(ev.MissingCaps, ", ")))
		}
	}
	if !r.btf {
		ev.Warnings = append(ev.Warnings,
			"kernel BTF not found ("+btfPath+"); the TC program is CO-RE free so loading may still work")
	}
	return ev
}

// PrereqStatus is the pre-start evaluation of the current host, computed
// without loading anything into the kernel. Doctor uses it to answer
// "would eBPF work here" before the first scan; observer_real applies the
// same verdict at start.
type PrereqStatus struct {
	Kernel      string
	BTF         bool
	CapsMissing []string
	Unsupported []string
	Warnings    []string
}

// EvaluatePrerequisites probes the current host. It never fails: unreadable
// sources surface as Warnings (or Unsupported when off-Linux).
func EvaluatePrerequisites() PrereqStatus {
	rep := defaultProbeSource().run()
	ev := evaluatePrereqs(rep)
	return PrereqStatus{
		Kernel:      rep.release,
		BTF:         rep.btf,
		CapsMissing: ev.MissingCaps,
		Unsupported: ev.Unsupported,
		Warnings:    ev.Warnings,
	}
}

// missingCaps returns the names of required capabilities absent from capEff.
func missingCaps(capEff uint64) []string {
	var out []string
	for _, c := range requiredCaps {
		if capEff&(1<<c.bit) == 0 {
			out = append(out, c.name)
		}
	}
	return out
}

// parseKernelRelease extracts the major.minor pair from a kernel release
// string such as "6.6.144", "5.15.0-rc7" or "6.18.40.1-microsoft-standard".
func parseKernelRelease(s string) (major, minor int, ok bool) {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || major < 0 || minor < 0 {
		return 0, 0, false
	}
	return major, minor, true
}

// parseCapEff extracts the CapEff bitmask from /proc/self/status content.
// Returns 0 when absent or unparsable (caller treats non-root + 0 as
// missing-everything, which is the safe reading).
func parseCapEff(status string) uint64 {
	line, ok := statusField(status, "CapEff:")
	if !ok {
		return 0
	}
	v, err := strconv.ParseUint(line, 16, 64)
	if err != nil {
		return 0
	}
	return v
}

// parseStatusUIDField extracts one field of a "Uid:\t0\t0\t0\t0" style status
// line. Field 1 is the effective uid. Returns -1 when absent or unparsable.
func parseStatusUIDField(status, key string) int {
	line, ok := statusField(status, key)
	if !ok {
		return -1
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return -1
	}
	v, err := strconv.Atoi(fields[1])
	if err != nil {
		return -1
	}
	return v
}

// statusField returns the trimmed remainder of the "Key:<value>" line.
func statusField(status, key string) (string, bool) {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, key) {
			return strings.TrimSpace(strings.TrimPrefix(line, key)), true
		}
	}
	return "", false
}
