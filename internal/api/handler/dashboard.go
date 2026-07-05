package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"mibee-steward/internal/db"
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

// ListConfigs handles GET /api/v1/dashboard/configs
func (h *DashboardHandler) ListConfigs(w http.ResponseWriter, r *http.Request) {
	configs, err := h.svc.ListConfigs(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list dashboard configs")
		return
	}
	Success(w, configs)
}

// CreateConfig handles POST /api/v1/dashboard/configs
func (h *DashboardHandler) CreateConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name            string `json:"name"`
		Type            string `json:"type"`
		DataSource      string `json:"data_source"`
		Query           string `json:"query"`
		RefreshInterval int64  `json:"refresh_interval"`
		Position        string `json:"position"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		Error(w, http.StatusBadRequest, "name is required")
		return
	}

	validTypes := map[string]bool{"gauge": true, "line": true, "bar": true, "pie": true}
	if !validTypes[req.Type] {
		Error(w, http.StatusBadRequest, "type must be one of: gauge, line, bar, pie")
		return
	}

	if req.DataSource == "" {
		req.DataSource = "prometheus"
	}
	if req.Position == "" {
		req.Position = "{}"
	}
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
		Position        string `json:"position"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		Error(w, http.StatusBadRequest, "name is required")
		return
	}

	validTypes := map[string]bool{"gauge": true, "line": true, "bar": true, "pie": true}
	if !validTypes[req.Type] {
		Error(w, http.StatusBadRequest, "type must be one of: gauge, line, bar, pie")
		return
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

// Query handles GET /api/v1/dashboard/query — proxies instant PromQL queries.
func (h *DashboardHandler) Query(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	if query == "" {
		Error(w, http.StatusBadRequest, "query parameter is required")
		return
	}
	ts := r.URL.Query().Get("time")

	body, err := h.svc.Query(r.Context(), query, ts)
	if err != nil {
		if errors.Is(err, &service.UpstreamError{}) {
			Error(w, http.StatusBadGateway, "data source unreachable")
			return
		}
		Error(w, http.StatusBadGateway, "failed to query data source")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// QueryRange handles GET /api/v1/dashboard/query_range — proxies range PromQL queries.
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
		if errors.Is(err, &service.UpstreamError{}) {
			Error(w, http.StatusBadGateway, "data source unreachable")
			return
		}
		Error(w, http.StatusBadGateway, "failed to query data source")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}
