// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

import (
	"context"
	"time"
)

// Result holds the outcome of a single probe execution.
type Result struct {
	Success      bool
	Latency      time.Duration
	ErrorMessage string
}

// Prober is the interface that all probe types must implement.
type Prober interface {
	Probe(ctx context.Context, target string, timeout time.Duration) (*Result, error)
}
