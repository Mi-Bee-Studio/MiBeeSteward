// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"net/http"
	"strconv"

	"mibee-steward/internal/service/probetarget"
)

// ProbeQualityHandler serves the egress-quality analysis (#608). Read-only
// over probe_results; the service does the aggregation.
type ProbeQualityHandler struct {
	service *probetarget.QualityService
}

// NewProbeQualityHandler constructs a ProbeQualityHandler.
func NewProbeQualityHandler(service *probetarget.QualityService) *ProbeQualityHandler {
	return &ProbeQualityHandler{service: service}
}

// GetQuality handles GET /api/v1/probe-quality?window=15 (minutes, optional,
// clamped to 5..1440, default from config).
func (h *ProbeQualityHandler) GetQuality(w http.ResponseWriter, r *http.Request) {
	window := 0
	if raw := r.URL.Query().Get("window"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 5 || v > 1440 {
			Error(w, http.StatusBadRequest, "window must be minutes between 5 and 1440")
			return
		}
		window = v
	}
	report, err := h.service.Analyze(r.Context(), window)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to analyze probe quality")
		return
	}
	Success(w, report)
}

// GetQualityHistory handles GET /api/v1/probe-quality/history?days=7 (7 or
// 30; hourly buckets for 7d, daily for 30d). Same verdict chain as the live
// window, replayed per bucket over the retention horizon.
func (h *ProbeQualityHandler) GetQualityHistory(w http.ResponseWriter, r *http.Request) {
	days := 7
	if raw := r.URL.Query().Get("days"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || (v != 7 && v != 30) {
			Error(w, http.StatusBadRequest, "days must be 7 or 30")
			return
		}
		days = v
	}
	report, err := h.service.History(r.Context(), days)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to aggregate probe quality history")
		return
	}
	Success(w, report)
}
