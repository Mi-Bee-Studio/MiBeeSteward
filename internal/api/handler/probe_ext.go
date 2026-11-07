// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"mibee-steward/internal/service/probeext"
)

// ProbeExtHandler serves the egress/path extension views (#716/#718/#719):
// current egress identity per vantage, latest path per target, and the
// manual trace trigger. Reads are read-only passthrough on the probeext
// service; the trigger mutates (one trace) so it lives behind probe:manage.
type ProbeExtHandler struct {
	svc *probeext.Service
}

// NewProbeExtHandler builds the handler.
func NewProbeExtHandler(svc *probeext.Service) *ProbeExtHandler {
	return &ProbeExtHandler{svc: svc}
}

// Egress godoc
// @Summary      Current egress identity per vantage
// @Description  Latest egress echo round per vantage: observed public IPs
// @Description  (with ASN), per-source results, and the local default-route
// @Description  gateway. Recording only - changes never notify (#716).
// @Tags         probes
// @Security     cookieAuth
// @Produce      json
// @Success      200 {object} probeext.EgressReportResponse
// @Failure      500 {object} ErrorResponse
// @Router       /probe-egress [get]
func (h *ProbeExtHandler) Egress(w http.ResponseWriter, r *http.Request) {
	views, err := h.svc.EgressSnapshot(r.Context())
	if err != nil {
		slog.Error("probe-egress: snapshot failed", "error", err)
		Error(w, http.StatusInternalServerError, "failed to load egress state")
		return
	}
	Success(w, map[string]any{"vantages": views})
}

// Paths godoc
// @Summary      Latest traced path per target and vantage
// @Description  The newest path sample for every traced (target, vantage):
// @Description  resolved IP, method, hop list, reached TTL, reply TTL.
// @Tags         probes
// @Security     cookieAuth
// @Produce      json
// @Success      200 {object} probeext.PathsResponse
// @Failure      500 {object} ErrorResponse
// @Router       /probe-paths [get]
func (h *ProbeExtHandler) Paths(w http.ResponseWriter, r *http.Request) {
	paths, err := h.svc.PathsSnapshot(r.Context())
	if err != nil {
		slog.Error("probe-paths: snapshot failed", "error", err)
		Error(w, http.StatusInternalServerError, "failed to load paths")
		return
	}
	if paths == nil {
		paths = []map[string]any{}
	}
	Success(w, map[string]any{"paths": paths})
}

// TargetPaths godoc
// @Summary      Path-trace history of one target
// @Tags         probes
// @Security     cookieAuth
// @Produce      json
// @Param        id path int true "Target ID"
// @Param        limit query int false "Max samples (default 50)"
// @Success      200 {object} probeext.PathsResponse
// @Failure      400 {object} ErrorResponse
// @Router       /probe-targets/{id}/paths [get]
func (h *ProbeExtHandler) TargetPaths(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid target id")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	paths, err := h.svc.ListTargetPaths(r.Context(), id, limit)
	if err != nil {
		slog.Error("probe-target paths: list failed", "error", err)
		Error(w, http.StatusInternalServerError, "failed to load path history")
		return
	}
	if paths == nil {
		paths = []probeext.PathSample{}
	}
	Success(w, map[string]any{"paths": paths})
}

// TraceNow godoc
// @Summary      Trace one target's path now (center vantage)
// @Description  Runs one synchronous zero-privilege TCP/ICMP TTL walk and
// @Description  stores it as a manual sample.
// @Tags         probes
// @Security     cookieAuth
// @Param        id path int true "Target ID"
// @Success      200 {object} probeext.PathSampleResponse
// @Failure      404 {object} ErrorResponse
// @Router       /probe-targets/{id}/trace [post]
func (h *ProbeExtHandler) TraceNow(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid target id")
		return
	}
	sample, err := h.svc.TraceNow(r.Context(), id)
	if err != nil {
		slog.Error("probe trace: failed", "target_id", id, "error", err)
		Error(w, http.StatusNotFound, "target not found")
		return
	}
	b, _ := json.Marshal(sample)
	Success(w, json.RawMessage(b))
}
