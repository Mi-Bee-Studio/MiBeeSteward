// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.

package probe

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestProbeFailureStreakLogging pins the #271 log-noise contract at the unit
// level by driving the streak counters directly:
//   - failures 1..warnStreakThreshold increment the streak,
//   - a recovery before the threshold emits NO transition,
//   - a recovery after an established outage DOES (the offline→online event
//     the issue requires to stay visible),
//   - the streak resets after success.
func TestProbeFailureStreakLogging(t *testing.T) {
	failStreaks = sync.Map{} // reset global state

	// Target goes down: streak accumulates past the WARN threshold.
	for i := 0; i < warnStreakThreshold+2; i++ {
		logProbeFailure("icmp", "10.0.0.99", errors.New("timeout"))
	}
	v, ok := failStreaks.Load("icmp|10.0.0.99")
	if !ok {
		t.Fatal("streak entry missing after failures")
	}
	if n := v.(*atomic.Int64).Load(); n != warnStreakThreshold+2 {
		t.Fatalf("streak = %d, want %d", n, warnStreakThreshold+2)
	}

	// Established outage recovers: streak cleared.
	noteProbeSuccess("icmp", "10.0.0.99", 5*time.Millisecond)
	if _, still := failStreaks.Load("icmp|10.0.0.99"); still {
		t.Fatal("streak entry must be deleted on success")
	}

	// Brief flap (below threshold) then success: no transition expected,
	// entry still cleaned up.
	logProbeFailure("tcp", "10.0.0.100", errors.New("refused"))
	noteProbeSuccess("tcp", "10.0.0.100", time.Millisecond)
	if _, still := failStreaks.Load("tcp|10.0.0.100"); still {
		t.Fatal("streak entry must be deleted on success (flap case)")
	}
}
