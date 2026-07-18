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
	"strconv"
)

// timeMsString formats a millisecond value as a trimmed decimal string with no
// trailing zeros (e.g. 1.5ms → "1.5", 2ms → "2"). Used for Evidence RawData.
func timeMsString(ms int64) string {
	// strconv.FormatInt gives whole ms; if sub-ms precision matters elsewhere
	// the caller can store the raw duration. For RTT we round to ms.
	return strconv.FormatInt(ms, 10)
}
