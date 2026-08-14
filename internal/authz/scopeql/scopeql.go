// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. A commercial license is available for use cases
// the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Package scopeql provides the shared SQL primitive that restricts an inventory
// query to the networks in a resolved object-level Scope (#138 Phase 2b). The
// device list has its own parallel impl in internal/service/device_repo.go
// (scopeClause, tied to DeviceFilter); this package is the general-purpose
// version the other read surfaces (changes, dashboard, stats, export) share so
// the "restricted + no grants → sees nothing" rule lives in exactly one place.
package scopeql

import (
	"strings"

	"mibee-steward/internal/domain"
)

// NetworkPredicate returns a SQL predicate (no leading AND/WHERE) plus bind args
// that test network_id membership against s:
//   - Global scope → ("1=1", nil): no restriction. Safe to AND into any WHERE
//     and to use as a sole predicate ("WHERE 1=1").
//   - Restricted, non-empty → ("<alias>.network_id IN (?,?,...)", args).
//   - Restricted, empty (closed mode, no grants) → ("0", nil): matches nothing,
//     so the whole row set is empty without extra special-casing.
//
// alias prefixes the network_id column (e.g. "d" → "d.network_id"); pass "" for
// a bare column reference.
func NetworkPredicate(s domain.Scope, alias string) (predicate string, args []any) {
	if s.IsGlobal() {
		return "1=1", nil
	}
	col := "network_id"
	if alias != "" {
		col = alias + ".network_id"
	}
	if len(s.NetworkIDs) == 0 {
		return "0", nil
	}
	marks := make([]string, len(s.NetworkIDs))
	args = make([]any, len(s.NetworkIDs))
	for i, id := range s.NetworkIDs {
		marks[i] = "?"
		args[i] = id
	}
	return col + " IN (" + strings.Join(marks, ",") + ")", args
}
