// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probetarget

import (
	"sync"

	"mibee-steward/internal/changedetect"
)

// probeFailedThreshold is how many consecutive failing runs a target needs
// before probe_failed is declared. Three was chosen over one deliberate
// flap-damping: a single lost packet on a 300s cadence must not page anyone,
// while 3×interval (15 min at the recommended cadence) is still well inside
// "the service is down" territory.
const probeFailedThreshold = 3

// transitionDetector is the probe engine's liveness state machine. It watches
// every center-executed result per target and declares transitions:
//
//	ok --(N consecutive fails)--> failing  → emits probe_failed
//	failing --(any success)--> ok          → emits probe_recovered
//
// Failures while already failing emit nothing (the state did not change); the
// receiving side's dedup/cooldown would collapse repeats anyway. State is
// in-memory: on restart a target whose persisted last_status already says
// failing is seeded AS failing without emitting — the missed transition stays
// quiet (the target is visibly failing in the probes UI), while a later
// recovery still emits normally.
type transitionDetector struct {
	mu     sync.Mutex
	states map[int64]*probeState
}

type probeState struct {
	failing bool
	streak  int // consecutive failures while not yet failing
}

// newTransitionDetector builds an empty detector.
func newTransitionDetector() *transitionDetector {
	return &transitionDetector{states: make(map[int64]*probeState)}
}

// observe feeds one result for a target and reports which change type to emit,
// if any. lastStatus is the target's persisted last_status BEFORE this result
// ("" when unknown), used only to seed first sight.
func (d *transitionDetector) observe(targetID int64, lastStatus string, status string) string {
	failed := status != probeStatusSuccess
	d.mu.Lock()
	defer d.mu.Unlock()

	st, ok := d.states[targetID]
	if !ok {
		// First sight this process: adopt the persisted state silently.
		st = &probeState{failing: lastStatus != "" && lastStatus != probeStatusSuccess}
		d.states[targetID] = st
	}

	if !failed {
		st.streak = 0
		if st.failing {
			st.failing = false
			return changedetect.ChangeTypeProbeRecovered
		}
		return ""
	}

	if st.failing {
		return "" // still failing, no transition
	}
	st.streak++
	if st.streak >= probeFailedThreshold {
		st.failing = true
		st.streak = 0
		return changedetect.ChangeTypeProbeFailed
	}
	return ""
}

// prune drops state for targets absent from present so deleted/disabled
// targets do not leak entries (mirrors the engine's nextDue pruning).
func (d *transitionDetector) prune(present map[int64]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id := range d.states {
		if !present[id] {
			delete(d.states, id)
		}
	}
}

// probeStatusSuccess is the single non-failing verdict ("fail" and "timeout"
// both count as failures).
const probeStatusSuccess = "success"
