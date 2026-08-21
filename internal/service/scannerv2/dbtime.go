// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, copy, modify, and redistribute it
// under those terms; see LICENSE for the full text. A commercial license is
// available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package scannerv2

import "time"

// DBTime renders t in the canonical text form for SQLite columns written by
// the raw-SQL store/runner layer: RFC3339 UTC, second precision.
//
// Binding a Go time.Time through modernc.org/sqlite serializes it as Go's
// String() ("2026-08-21 06:19:41.627875222 +0000 UTC"), which SQLite's
// date()/datetime() cannot parse — every date() over those columns returned
// NULL, and text comparisons against other formats misordered (#257). This
// matches the formats already used by the heartbeat store (checked_at), the
// audit query params, and the retention sweeper's RFC3339 cutoffs, so string
// comparisons across those paths stay consistent.
func DBTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}
