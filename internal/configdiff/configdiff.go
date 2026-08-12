// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

// Package configdiff computes unified text diffs between device-configuration
// snapshots — the "diff" half of the Oxidized/RANCID-style config-backup
// feature (#137). It is a pure, dependency-light utility (backed by the already
// vendored go-difflib) so the pull probe, storage, and change-detection layers
// can all share one diff implementation.
//
// A device running-config snapshot is plain text (newline-separated), so a
// standard unified diff (the `@@ ... @@` format with `+`/`-` lines) is the
// right shape: it is what operators expect from `diff -u`, what the device
// detail page will render side-by-side, and what the change-detection engine
// can attach to a device_config_changed event.
package configdiff

import (
	"fmt"

	"github.com/pmezard/go-difflib/difflib"
)

// ContextLines is the number of unchanged context lines shown around each diff
// hunk. Mirrors `diff -u` (3) so the output is familiar to operators and
// survives small unrelated trailing-line shifts.
const ContextLines = 3

// Diff returns a unified diff between oldText and newText. The result is the
// empty string when the two texts are identical (the common case on a
// rescan that fetches an unchanged running-config — callers use this to decide
// whether to persist a new version + emit a change event).
//
// oldLabel/newLabel label the `---`/`+++` headers (e.g. a version stamp or
// "running-config @ 2026-08-12T14:00:00Z"). They are metadata only; they do not
// affect the diff content.
func Diff(oldLabel, oldText, newLabel, newText string) (string, error) {
	if oldText == newText {
		return "", nil
	}
	d := difflib.UnifiedDiff{
		A:        difflib.SplitLines(oldText),
		B:        difflib.SplitLines(newText),
		FromFile: oldLabel,
		ToFile:   newLabel,
		Context:  ContextLines,
	}
	out, err := difflib.GetUnifiedDiffString(d)
	if err != nil {
		return "", fmt.Errorf("compute config diff: %w", err)
	}
	return out, nil
}

// MustDiff is Diff without the error (the underlying difflib never errors on
// in-memory slices; the error return exists only to satisfy the io.Writer-based
// signature). For callers that have only in-memory text it removes the
// boilerplate.
func MustDiff(oldLabel, oldText, newLabel, newText string) string {
	out, err := Diff(oldLabel, oldText, newLabel, newText)
	if err != nil {
		// Unreachable for in-memory inputs; difflib.GetUnifiedDiffString only
		// errors on a failing io.Writer, and the string variant uses a buffer.
		return ""
	}
	return out
}

// Changed is a cheap pre-check: do the two configs differ at all? It is the
// allocation-free gate callers use before building the full diff.
func Changed(old, newText string) bool { return old != newText }

// HasChange reports whether a diff produced by Diff/MustDiff contains any
// change. Under this package's contract an empty string means "identical", so
// HasChange is simply a non-empty check — but spelling it out makes the call
// site read correctly at the storage/change-detection boundary.
func HasChange(diff string) bool { return diff != "" }
