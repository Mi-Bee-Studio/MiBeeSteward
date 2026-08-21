// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, copy, modify, and redistribute it
// under those terms; see LICENSE for the full text. A commercial license is
// available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probe

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Log-noise reduction for periodic probes (#271).
//
// A device that is offline fails EVERY cycle by design: two days of field logs
// showed 7518 "probe failed" ERROR lines for known-dead targets, drowning the
// ~1459 real errors (SQLITE_BUSY writes). Consecutive-failure streaks drive
// the level instead:
//
//   - first warnStreakThreshold failures of a streak → WARN (a target that
//     just went down is news),
//   - after that → DEBUG, sampled every debugSampleEvery-th failure so the
//     "still failing" heartbeat stays greppable without flooding,
//   - recovery after a long streak → INFO (the offline→online transition),
//   - the streak map is unbounded in theory but keyed by (method, target)
//     where targets are probe/heartbeat configs — dozens of entries, not
//     thousands; entries are deleted on success.
const (
	warnStreakThreshold = 3
	debugSampleEvery    = 20
)

var failStreaks sync.Map // "method|target" -> *atomic.Int64

// logProbeFailure records one failed probe attempt and logs it at the level
// the current streak warrants. Caller-side errors (unparseable target, bad
// config) never go through here — they stay ERROR; only execution failures
// against the target do.
func logProbeFailure(method, target string, err error) {
	streak, _ := failStreaks.LoadOrStore(method+"|"+target, new(atomic.Int64))
	n := streak.(*atomic.Int64).Add(1)
	switch {
	case n <= warnStreakThreshold:
		slog.Warn("probe failed", "method", method, "target", target, "error", err, "streak", n)
	case n%debugSampleEvery == 0:
		slog.Debug("probe target still failing", "method", method, "target", target, "error", err, "streak", n)
	}
}

// noteProbeSuccess clears a target's failure streak, emitting an INFO
// transition when it recovers from an established outage (>= threshold
// failures). Routine successes stay at their existing Debug logging — this
// only owns the transition event.
func noteProbeSuccess(method, target string, latency time.Duration) {
	if v, ok := failStreaks.LoadAndDelete(method + "|" + target); ok {
		if n := v.(*atomic.Int64).Load(); n >= warnStreakThreshold {
			slog.Info("probe target recovered", "method", method, "target", target,
				"after_failures", n, "latency", latency)
		}
	}
}
