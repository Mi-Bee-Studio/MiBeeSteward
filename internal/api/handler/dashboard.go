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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
)

// DashboardHandler handles HTTP requests for dashboard config and query proxy endpoints.
type DashboardHandler struct {
	svc *service.DashboardService
}

// NewDashboardHandler creates a new DashboardHandler.
func NewDashboardHandler(svc *service.DashboardService) *DashboardHandler {
	return &DashboardHandler{svc: svc}
}

// ListConfigs handles GET /api/v1/dashboard/configs. The response is an object
// ({configs, total}), not a bare array, the dashboard page reads res.configs
// and a bare array made every custom widget invisible (#247).
func (h *DashboardHandler) ListConfigs(w http.ResponseWriter, r *http.Request) {
	configs, err := h.svc.ListConfigs(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list dashboard configs")
		return
	}
	Success(w, struct {
		Configs []db.DashboardConfig `json:"configs"`
		Total   int                  `json:"total"`
	}{Configs: configs, Total: len(configs)})
}

// Overview handles GET /api/v1/dashboard/overview, the aggregated payload that
// powers the default dashboard (device totals/distributions, recent scan
// activity, offline-device list). Computed server-side over the full dataset.
func (h *DashboardHandler) Overview(w http.ResponseWriter, r *http.Request) {
	resp, err := h.svc.Overview(r.Context(), domain.ScopeFromContext(r.Context()))
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to load dashboard overview")
		return
	}
	Success(w, resp)
}

// CreateConfig handles POST /api/v1/dashboard/configs
func (h *DashboardHandler) CreateConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name            string `json:"name"`
		Type            string `json:"type"`
		DataSource      string `json:"data_source"`
		Query           string `json:"query"`
		RefreshInterval int64  `json:"refresh_interval"`
		Position        int64  `json:"position"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	dataSource, err := validateWidgetConfig(req.Name, req.Type, req.DataSource, req.Query)
	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	req.DataSource = dataSource

	// position <= 0 = not specified; the service assigns max(position)+1 so
	// new widgets land after existing ones without the client computing it.
	if req.RefreshInterval <= 0 {
		req.RefreshInterval = 30
	}

	result, err := h.svc.CreateConfig(r.Context(), db.CreateDashboardConfigParams{
		Name:            req.Name,
		Type:            req.Type,
		DataSource:      req.DataSource,
		Query:           req.Query,
		RefreshInterval: req.RefreshInterval,
		Position:        req.Position,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to create dashboard config")
		return
	}

	Created(w, result)
}

// UpdateConfig handles PUT /api/v1/dashboard/configs/{id}
func (h *DashboardHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid config ID")
		return
	}

	var req struct {
		Name            string `json:"name"`
		Type            string `json:"type"`
		DataSource      string `json:"data_source"`
		Query           string `json:"query"`
		RefreshInterval int64  `json:"refresh_interval"`
		Position        int64  `json:"position"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	dataSource, err := validateWidgetConfig(req.Name, req.Type, req.DataSource, req.Query)
	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}
	req.DataSource = dataSource

	if req.RefreshInterval <= 0 {
		req.RefreshInterval = 30
	}

	result, err := h.svc.UpdateConfig(r.Context(), db.UpdateDashboardConfigParams{
		ID:              id,
		Name:            req.Name,
		Type:            req.Type,
		DataSource:      req.DataSource,
		Query:           req.Query,
		RefreshInterval: req.RefreshInterval,
		Position:        req.Position,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to update dashboard config")
		return
	}

	Success(w, result)
}

// DeleteConfig handles DELETE /api/v1/dashboard/configs/{id}
func (h *DashboardHandler) DeleteConfig(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid config ID")
		return
	}

	err = h.svc.DeleteConfig(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to delete dashboard config")
		return
	}

	Success(w, map[string]string{"message": "dashboard config deleted"})
}

// Query handles GET /api/v1/dashboard/query, proxies instant PromQL queries.
func (h *DashboardHandler) Query(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	if query == "" {
		Error(w, http.StatusBadRequest, "query parameter is required")
		return
	}
	ts := r.URL.Query().Get("time")

	body, err := h.svc.Query(r.Context(), query, ts)
	if err != nil {
		var upErr *service.UpstreamError
		if errors.As(err, &upErr) {
			Error(w, http.StatusBadGateway, "data source unreachable")
			return
		}
		Error(w, http.StatusBadGateway, "failed to query data source")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// QueryRange handles GET /api/v1/dashboard/query_range, proxies range PromQL queries.
func (h *DashboardHandler) QueryRange(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	query := q.Get("query")
	start := q.Get("start")
	end := q.Get("end")
	step := q.Get("step")

	if query == "" {
		Error(w, http.StatusBadRequest, "query parameter is required")
		return
	}
	if start == "" || end == "" || step == "" {
		Error(w, http.StatusBadRequest, "start, end, and step parameters are required")
		return
	}

	body, err := h.svc.QueryRange(r.Context(), query, start, end, step)
	if err != nil {
		var upErr *service.UpstreamError
		if errors.As(err, &upErr) {
			Error(w, http.StatusBadGateway, "data source unreachable")
			return
		}
		Error(w, http.StatusBadGateway, "failed to query data source")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// builtinWidgetTemplates maps the "builtin:" template keys (stored in the
// query column of dashboard_configs) to the widget type each preset renders
// as. The frontend preset gallery sends one of these keys with
// data_source=builtin; validation rejects anything else so a typo or a
// frontend/backend drift can't create a permanently-blank widget. Adding a
// preset = one entry here + one gallery card in WidgetPicker.svelte.
var builtinWidgetTemplates = map[string]string{
	"builtin:device_status":    "pie",
	"builtin:device_types":     "pie",
	"builtin:device_locations": "bar",
	"builtin:online_rate":      "gauge",
	"builtin:recent_changes":   "list",
	"builtin:offline_devices":  "list",
	"builtin:scan_activity":    "list",
	"builtin:probe_status":     "list",
}

// validateWidgetConfig is the pure validation shared by CreateConfig and
// UpdateConfig (previously duplicated inline in both). It returns the
// defaulted data_source ("prometheus" when empty) or an error explaining the
// rejection. Rules:
//   - data_source "prometheus"/"victoriametrics" (both proxy to the same
//     upstream, victoriametrics is the historical alias the schema allows):
//     chart types only (gauge/line/bar/pie) and a non-empty PromQL query, a
//     widget with nothing to execute is dead UI.
//   - data_source "builtin": query must be a whitelisted template key and the
//     type must match the template's rendering type (list presets are list,
//     chart presets are their chart type).
func validateWidgetConfig(name, widgetType, dataSource, query string) (string, error) {
	if name == "" {
		return "", errors.New("name is required")
	}
	if dataSource == "" {
		dataSource = "prometheus"
	}

	chartTypes := map[string]bool{"gauge": true, "line": true, "bar": true, "pie": true}
	switch dataSource {
	case "prometheus", "victoriametrics":
		if !chartTypes[widgetType] {
			return "", errors.New("type must be one of: gauge, line, bar, pie")
		}
		if query == "" {
			return "", errors.New("query is required for prometheus widgets")
		}
	case "builtin":
		wantType, ok := builtinWidgetTemplates[query]
		if !ok {
			return "", fmt.Errorf("unknown builtin widget template: %s", query)
		}
		if widgetType != wantType {
			return "", fmt.Errorf("builtin template %s must use type %s", query, wantType)
		}
	default:
		return "", errors.New("data_source must be one of: prometheus, builtin")
	}
	return dataSource, nil
}
