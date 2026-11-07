// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probeext

import "mibee-steward/internal/db"

func testTarget(module, target string) db.ProbeTarget {
	return db.ProbeTarget{ID: 1, Name: "t", Module: module, Target: target}
}
