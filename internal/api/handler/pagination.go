// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"net/http"
	"strconv"
)

// ParsePagination applies the API-contract pagination policy (#274) to the
// limit/offset query parameters:
//
//   - unset (or 0) → def (the endpoint's documented default)
//   - malformed or negative → 400 (a client bug gets an answer, not a silent floor)
//   - limit > maxLimit → clamped (never an error; the response echoes the
//     EFFECTIVE limit so clients can detect the clamp)
//   - offset < 0 → 400
//
// def/maxLimit mirror the service-layer clamps of each endpoint (those remain
// as a backstop). ok=false means the 400 was already written, return immediately.
func ParsePagination(w http.ResponseWriter, r *http.Request, def, maxLimit int64) (limit, offset int64, ok bool) {
	limit = def
	offset = 0
	q := r.URL.Query()
	if v := q.Get("limit"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			Error(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return 0, 0, false
		}
		switch {
		case n == 0:
			limit = def
		case n > maxLimit:
			limit = maxLimit
		default:
			limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			Error(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return 0, 0, false
		}
		offset = n
	}
	return limit, offset, true
}

// SuccessList writes the standard list envelope of the API contract (#274):
//
//	{ "<key>": [...], "total": N, "limit": L, "offset": O }
//
// key is the resource-named array field (devices, users, changes, ...). total
// is the FILTERED count (the number of rows matching the query, not the page
// size). limit/offset echo the effective pagination so clients can detect a
// server-side clamp. Non-paginated collections (topology graphs, per-device
// sub-lists) may use Success with {key, total} only, they are complete lists.
func SuccessList(w http.ResponseWriter, key string, items interface{}, total, limit, offset int64) {
	Success(w, map[string]interface{}{
		key:      items,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}
