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
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/service/diagnostics"
)

// DeviceDiagnosisHandler serves the per-device network-anomaly verdict
// (#761): address timeline with liveness facts, classified findings with an
// evidence chain, and sibling identity rows. Read-only; the classification
// lives in the diagnostics service.
type DeviceDiagnosisHandler struct {
	svc *diagnostics.Service
}

// NewDeviceDiagnosisHandler constructs the handler over the diagnosis service.
func NewDeviceDiagnosisHandler(svc *diagnostics.Service) *DeviceDiagnosisHandler {
	return &DeviceDiagnosisHandler{svc: svc}
}

// Get handles GET /api/v1/devices/{id}/diagnosis. Any logged-in user may
// read; the verdict is computed on demand from persisted scan facts.
func (h *DeviceDiagnosisHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid device id")
		return
	}
	out, err := h.svc.Diagnose(r.Context(), id)
	if err != nil {
		if errors.Is(err, diagnostics.ErrDeviceNotFound) {
			Error(w, http.StatusNotFound, "device not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to compute diagnosis")
		return
	}
	Success(w, out)
}
