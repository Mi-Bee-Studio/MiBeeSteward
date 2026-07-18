// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package classify

import "regexp"

// mysqlVersionRE matches a MySQL/MariaDB/Percona version string embedded in
// the binary greeting packet (the version is ASCII, terminated by 0x00). The
// pattern accepts digit.digit.digit with an optional suffix (-MariaDB, -log,
// -Percona, etc.). Robust to the binary framing because we anchor on the
// version shape rather than a magic prefix.
var mysqlVersionRE = regexp.MustCompile(`(\d+\.\d+\.\d+[-\w.]*(?:-MariaDB|-Percona|-log)?[-\w.]*)`)

// extractMySQLVersion pulls the version substring out of a MySQL greeting.
// Returns "" if no version-shaped substring is present.
func extractMySQLVersion(b string) string {
	m := mysqlVersionRE.FindString(b)
	return m
}
