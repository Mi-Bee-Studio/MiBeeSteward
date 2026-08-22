// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package agent

import (
	"context"
	"log/slog"
	"sync"
)

// LogRing is a slog.Handler that tees every log line into a bounded in-memory
// ring while delegating to the real handler unchanged. It exists for the
// "logs-tail" remote-ops command (#278): an agent logging to stderr/journald
// can't read those sinks back portably, but it CAN keep the last N lines it
// produced and ship them over the command channel on request.
type LogRing struct {
	mu    sync.Mutex
	lines []string
	cap   int
	next  slog.Handler
}

// NewLogRing wraps next (the process's real handler; nil → drop-through with
// ring only). cap ≤0 → 200 lines.
func NewLogRing(next slog.Handler, capacity int) *LogRing {
	if capacity <= 0 {
		capacity = 200
	}
	return &LogRing{lines: make([]string, 0, capacity), cap: capacity, next: next}
}

// Enabled mirrors the wrapped handler's level gate (nil next → enabled).
func (r *LogRing) Enabled(_ context.Context, l slog.Level) bool {
	if r.next == nil {
		return true
	}
	return r.next.Enabled(context.Background(), l)
}

// Handle records one formatted line into the ring, then forwards to next.
func (r *LogRing) Handle(ctx context.Context, rec slog.Record) error {
	line := rec.Level.String() + " " + rec.Message
	rec.Attrs(func(a slog.Attr) bool {
		line += " " + a.Key + "=" + a.Value.String()
		return true
	})
	r.mu.Lock()
	if len(r.lines) >= r.cap {
		r.lines = r.lines[1:]
	}
	r.lines = append(r.lines, line)
	r.mu.Unlock()
	if r.next != nil {
		return r.next.Handle(ctx, rec)
	}
	return nil
}

// WithAttrs delegates to next and shares the same ring.
func (r *LogRing) WithAttrs(attrs []slog.Attr) slog.Handler {
	if r.next == nil {
		return r
	}
	return NewLogRing(r.next.WithAttrs(attrs), r.cap)
}

// WithGroup delegates to next and shares the same ring.
func (r *LogRing) WithGroup(name string) slog.Handler {
	if r.next == nil {
		return r
	}
	return NewLogRing(r.next.WithGroup(name), r.cap)
}

// Lines returns a copy of the ring, oldest first.
func (r *LogRing) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.lines))
	copy(out, r.lines)
	return out
}
