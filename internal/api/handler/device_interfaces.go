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

// DeviceInterfacesHandler serves the per-device interface census (#529):
// the IF-MIB + ipAddrTable port list — ifIndex/name/description/MAC/speed
// and the IPv4 each port answers at. This is the multi-homed detail the
// single devices.ip_address row can't express.
type DeviceInterfacesHandler struct {
	queries *db.Queries
}

// NewDeviceInterfacesHandler constructs the handler.
func NewDeviceInterfacesHandler(queries *db.Queries) *DeviceInterfacesHandler {
	return &DeviceInterfacesHandler{queries: queries}
}

type interfaceEntry struct {
	ID        int64  `json:"id"`
	IfIndex   int    `json:"if_index"`
	IfName    string `json:"if_name"`
	IfDescr   string `json:"if_descr,omitempty"`
	MAC       string `json:"mac_address,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	SpeedMbps int64  `json:"speed,omitempty"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// ListByDevice handles GET /api/v1/devices/{id}/interfaces. Any logged-in
// user may read. Ordered by ifIndex.
func (h *DeviceInterfacesHandler) ListByDevice(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid device id")
		return
	}
	rows, err := h.queries.ListDeviceInterfaces(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to query interfaces")
		return
	}
	out := make([]interfaceEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, interfaceEntry{
			ID:        row.ID,
			IfIndex:   int(row.IfIndex),
			IfName:    row.IfName,
			IfDescr:   row.IfDescr,
			MAC:       row.MacAddress,
			IPAddress: row.IpAddress,
			SpeedMbps: row.Speed,
			FirstSeen: row.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:  row.LastSeen.UTC().Format(time.RFC3339),
		})
	}
	Success(w, map[string]any{"interfaces": out, "total": len(out)})
}
