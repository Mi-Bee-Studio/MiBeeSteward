// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"encoding/json"
	"net/http"

	"mibee-steward/internal/service/discovery"
)

// wellKnownResponse is the /.well-known/mibee-service payload (Scout docs/02
// §8.1). Exactly four keys — the App's subnet scan hits this endpoint to
// classify a discovered service by type, and anything beyond the identity
// (addresses, capabilities, credentials) would be a disclosure regression on
// an unauthenticated route.
type wellKnownResponse struct {
	Service string `json:"service"`
	Name    string `json:"name"`
	Ver     string `json:"ver"`
	ID      string `json:"id"`
}

// WellKnownHandler serves GET /.well-known/mibee-service (#729): the
// unauthenticated, minimal-disclosure identity endpoint of the ecosystem
// service discovery protocol. Registered in the PUBLIC route section (same
// posture as /health and /metrics: leaks no secrets, and the App cannot
// authenticate before it has discovered the instance).
func WellKnownHandler(ident discovery.Identity, ver string) http.HandlerFunc {
	resp := wellKnownResponse{
		Service: "steward",
		Name:    ident.Name,
		Ver:     ver,
		ID:      ident.ID,
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			// Header is already sent; nothing actionable mid-encode.
			return
		}
	}
}
