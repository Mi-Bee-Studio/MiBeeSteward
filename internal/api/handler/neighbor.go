// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/db"
)

// NeighborHandler serves L2-adjacency data from the device_neighbors table.
// Used by the device-detail Neighbors panel and the /topology view.
type NeighborHandler struct {
	queries *db.Queries
}

// NewNeighborHandler constructs the handler. queries is the center's *db.Queries.
func NewNeighborHandler(queries *db.Queries) *NeighborHandler {
	return &NeighborHandler{queries: queries}
}

// neighborResponseEntry is one neighbor edge enriched with the neighbor
// device's registry info (name/IP/type/status) when that device has itself
// been scanned. Fields are pointers so they JSON-omit when the neighbor is
// unidentified (no matching device row).
type neighborResponseEntry struct {
	ID               int64   `json:"id"`
	DeviceID         int64   `json:"device_id"`
	NeighborDeviceID *int64  `json:"neighbor_device_id"`
	NeighborMAC      string  `json:"neighbor_mac"`
	Protocol         string  `json:"protocol"`
	LocalPort        *string `json:"local_port"`
	RemotePort       *string `json:"remote_port"`
	NeighborName     *string `json:"neighbor_name"`
	NeighborIP       *string `json:"neighbor_ip"`
	NeighborType     *string `json:"neighbor_type"`
	NeighborStatus   *string `json:"neighbor_status"`
	FirstSeen        *string `json:"first_seen"`
	LastSeen         *string `json:"last_seen"`
}

// ListByDevice handles GET /api/v1/devices/{id}/neighbors — the L2 neighbors
// of one device, enriched with the neighbor device's name/IP/type where the
// neighbor has been scanned. Any logged-in user may read.
func (h *NeighborHandler) ListByDevice(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid device id")
		return
	}
	rows, err := h.queries.ListDeviceNeighborsWithDevice(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to query neighbors")
		return
	}
	out := make([]neighborResponseEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, neighborResponseEntry{
			ID:               row.ID,
			DeviceID:         row.DeviceID,
			NeighborDeviceID: row.ResolvedDeviceID, // JOIN result — non-nil when the neighbor MAC matches a scanned device
			NeighborMAC:      row.NeighborMac,
			Protocol:         row.Protocol,
			LocalPort:        row.LocalPort,
			RemotePort:       row.RemotePort,
			NeighborName:     row.NeighborName,
			NeighborIP:       row.NeighborIp,
			NeighborType:     row.NeighborType,
			NeighborStatus:   row.NeighborStatus,
			FirstSeen:        timeStr(row.FirstSeen),
			LastSeen:         timeStr(row.LastSeen),
		})
	}
	Success(w, map[string]any{"neighbors": out, "total": len(out)})
}

// timeStr formats a *time.Time as an RFC3339 string pointer, returning nil
// when the input is nil so the field omits from JSON rather than rendering as
// null/zero-time.
func timeStr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}
