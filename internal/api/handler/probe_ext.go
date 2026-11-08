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
	"time"

	"mibee-steward/internal/service/probeext"
)

// ProbeExtHandler serves the egress/path extension views (#716/#718/#719):
// current egress identity per vantage, latest path per target, and the
// manual trace trigger. Reads are read-only passthrough on the probeext
// service; the trigger mutates (one trace) so it lives behind probe:manage.
type ProbeExtHandler struct {
	svc      *probeext.Service
	episodes *probeext.EpisodeService
}

// NewProbeExtHandler builds the handler.
func NewProbeExtHandler(svc *probeext.Service, episodes *probeext.EpisodeService) *ProbeExtHandler {
	return &ProbeExtHandler{svc: svc, episodes: episodes}
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

// Episodes godoc
// @Summary      Quality degradation episodes
// @Description  Relative-baseline degradation episodes (#720): cross-
// @Description  confirmed impact with attribution. active=1 returns only
// @Description  unresolved episodes; days bounds the history window.
// @Tags         probes
// @Security     cookieAuth
// @Param        days query int false "History window in days (default 1)"
// @Param        active query int false "1 = only unresolved episodes"
// @Success      200 {object} probeext.EpisodesResponse
// @Failure      500 {object} ErrorResponse
// @Router       /probe-quality/episodes [get]
func (h *ProbeExtHandler) Episodes(w http.ResponseWriter, r *http.Request) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 30 {
		days = 1
	}
	since := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)
	episodes, err := h.episodes.ListEpisodesSince(r.Context(), since)
	if err != nil {
		slog.Error("probe episodes: list failed", "error", err)
		Error(w, http.StatusInternalServerError, "failed to list episodes")
		return
	}
	if r.URL.Query().Get("active") == "1" {
		var active []probeext.QualityEpisode
		for _, e := range episodes {
			if e.ResolvedAt == "" {
				active = append(active, e)
			}
		}
		episodes = active
	}
	if episodes == nil {
		episodes = []probeext.QualityEpisode{}
	}
	Success(w, probeext.EpisodesResponse{Episodes: episodes})
}
