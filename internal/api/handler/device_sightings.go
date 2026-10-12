// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/db"
)

// DeviceSightingsHandler serves the address-observation history (#527/#529):
// where a device was seen, at which address, via which vantage (center-local
// or a specific agent), from which pipeline source. The input rows come from
// the same writers the device bridge runs on every apply, plus the discovery
// funnel's passive sightings.
type DeviceSightingsHandler struct {
	queries *db.Queries
}

// NewDeviceSightingsHandler constructs the handler. queries is the center's
// *db.Queries.
func NewDeviceSightingsHandler(queries *db.Queries) *DeviceSightingsHandler {
	return &DeviceSightingsHandler{queries: queries}
}

// sightingEntry is one history row, newest-first.
type sightingEntry struct {
	ID         int64  `json:"id"`
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address,omitempty"`
	NetworkID  *int64 `json:"network_id,omitempty"`
	Vantage    string `json:"vantage,omitempty"` // "" = center-local, else agent id
	Source     string `json:"source,omitempty"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
	SeeCount   int64  `json:"see_count"`
}

// ListByDevice handles GET /api/v1/devices/{id}/sightings?limit=&vantage=.
// Any logged-in user may read. limit defaults to 50 (max 500); vantage=""
// returns every stream.
func (h *DeviceSightingsHandler) ListByDevice(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid device id")
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	vantage := r.URL.Query().Get("vantage")

	rows, err := h.queries.ListDeviceSightings(r.Context(), db.ListDeviceSightingsParams{
		DeviceID: id,
		Column2:  vantage, // first leg of the "empty filter = all streams" clause
		Vantage:  vantage,
		Limit:    int64(limit),
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to query sightings")
		return
	}
	out := make([]sightingEntry, 0, len(rows))
	for _, row := range rows {
		var networkID *int64
		if row.NetworkID != 0 {
			v := row.NetworkID
			networkID = &v
		}
		out = append(out, sightingEntry{
			ID:         row.ID,
			IPAddress:  row.IpAddress,
			MACAddress: row.MacAddress,
			NetworkID:  networkID,
			Vantage:    row.Vantage,
			Source:     row.Source,
			FirstSeen:  row.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:   row.LastSeen.UTC().Format(time.RFC3339),
			SeeCount:   row.SeeCount,
		})
	}
	Success(w, map[string]any{"sightings": out, "total": len(out)})
}
