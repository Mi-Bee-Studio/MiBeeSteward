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

// DeviceSpeaksHandler serves a device's speaks-with traffic profile (#500):
// the per-peer aggregates folded from the passive observer's flow samples.
type DeviceSpeaksHandler struct {
	queries *db.Queries
}

// NewDeviceSpeaksHandler constructs the handler.
func NewDeviceSpeaksHandler(queries *db.Queries) *DeviceSpeaksHandler {
	return &DeviceSpeaksHandler{queries: queries}
}

// speakRow is one peer aggregate. peer_device_id/peer_name are set when the
// peer is itself an inventory device (LAN-internal conversation); external
// peers carry only the IP and byte totals.
type speakRow struct {
	PeerIP       string  `json:"peer_ip"`
	PeerDeviceID *int64  `json:"peer_device_id"`
	PeerName     *string `json:"peer_name"`
	PeerDeviceIP *string `json:"peer_device_ip"`
	BytesOut     int64   `json:"bytes_out"`
	BytesIn      int64   `json:"bytes_in"`
	FirstSeen    string  `json:"first_seen"`
	LastSeen     string  `json:"last_seen"`
}

// ListByDevice handles GET /api/v1/devices/{id}/speaks — the device's
// traffic profile, heaviest peers first, capped at 100 rows.
func (h *DeviceSpeaksHandler) ListByDevice(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid device id")
		return
	}
	rows, err := h.queries.ListDeviceSpeaks(r.Context(), db.ListDeviceSpeaksParams{
		DeviceID: id,
		Limit:    100,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to query speaks-with profile")
		return
	}
	out := make([]speakRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, speakRow{
			PeerIP:       row.PeerIp,
			PeerDeviceID: row.PeerDeviceID,
			PeerName:     row.PeerName,
			PeerDeviceIP: row.PeerDeviceIp,
			BytesOut:     row.BytesOut,
			BytesIn:      row.BytesIn,
			FirstSeen:    row.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:     row.LastSeen.UTC().Format(time.RFC3339),
		})
	}
	Success(w, map[string]any{"speaks": out, "total": len(out)})
}
