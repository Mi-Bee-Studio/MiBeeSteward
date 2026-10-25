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

// probeFailedThreshold is how many consecutive failing runs a track needs
// before probe_failed is declared. Three was chosen over one deliberate
// flap-damping: a single lost packet on a 300s cadence must not page anyone,
// while 3×interval (15 min at the recommended cadence) is still well inside
// "the service is down" territory.
const probeFailedThreshold = 3

// transitionDetector is the probe engine's liveness state machine, keyed per
// (target, vantage) track — the center's own execution track and each agent's
// reporting track declare failures independently (a site can be fine from the
// center and dead from an agent's network, which is exactly the signal worth
// notifying). All tracks of one target share the notification identity
// (source_ref probe/<id>, rule cooldown key), so a site failing on every
// vantage still produces one dispatch per rule cooldown window.
//
//	ok --(N consecutive fails)--> failing  → emits probe_failed
//	failing --(any success)--> ok          → emits probe_recovered
//
// Failures while already failing emit nothing (the state did not change); the
// receiving side's dedup/cooldown would collapse repeats anyway. State is
// in-memory: the center track seeds from the target's persisted last_status
// on first sight (silently — the target is already visibly failing in the
// probes UI, no synthesized stale alert); agent tracks have no persisted
// per-vantage state and start fresh, so an already-failing agent track
// re-declares after threshold more failures following a center restart.
type transitionDetector struct {
	mu     sync.Mutex
	states map[trackKey]*probeState
}

type trackKey struct {
	targetID int64
	vantage  string
}

type probeState struct {
	failing bool
	streak  int // consecutive failures while not yet failing
}

// newTransitionDetector builds an empty detector.
func newTransitionDetector() *transitionDetector {
	return &transitionDetector{states: make(map[trackKey]*probeState)}
}

// observe feeds one result for a (target, vantage) track and reports which
// change type to emit, if any. lastStatus is the track's persisted status
// BEFORE this result; only the center track has one ("" when unknown), which
// is used solely to seed first sight.
func (d *transitionDetector) observe(targetID int64, vantage, lastStatus, status string) string {
	failed := status != probeStatusSuccess
	d.mu.Lock()
	defer d.mu.Unlock()

	key := trackKey{targetID: targetID, vantage: vantage}
	st, ok := d.states[key]
	if !ok {
		// First sight this process: adopt the persisted state silently.
		st = &probeState{failing: lastStatus != "" && lastStatus != probeStatusSuccess}
		d.states[key] = st
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

// prune drops all tracks of targets absent from present so deleted/disabled
// targets do not leak entries (mirrors the engine's nextDue pruning; agent
// tracks die with their target, not with their plan).
func (d *transitionDetector) prune(present map[int64]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range d.states {
		if !present[k.targetID] {
			delete(d.states, k)
		}
	}
}

// probeStatusSuccess is the single non-failing verdict ("fail" and "timeout"
// both count as failures).
const probeStatusSuccess = "success"
