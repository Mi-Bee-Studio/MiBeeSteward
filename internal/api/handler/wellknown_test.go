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
	"net/http/httptest"
	"testing"

	"mibee-steward/internal/service/discovery"
)

// The well-known identity endpoint is a public, minimal-disclosure contract
// (Scout docs/02 §8.1): exactly four keys, no addresses, no tokens, no
// capabilities. Anything beyond the shape below is a disclosure regression.
func TestWellKnownHandlerShape(t *testing.T) {
	ident := discovery.Identity{ID: "0123abcd", Name: "steward-lan"}
	h := WellKnownHandler(ident, "0.9.1-test")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/mibee-service", nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	if len(body) != 4 {
		t.Fatalf("body has %d keys (%v), want exactly 4 — extra keys are a disclosure regression", len(body), body)
	}
	if body["service"] != "steward" {
		t.Fatalf("service = %q, want %q", body["service"], "steward")
	}
	if body["id"] != "0123abcd" || body["name"] != "steward-lan" || body["ver"] != "0.9.1-test" {
		t.Fatalf("identity fields mismatch: %+v", body)
	}
}
