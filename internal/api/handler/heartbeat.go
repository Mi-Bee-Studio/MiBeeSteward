package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
)

// HeartbeatHandler handles HTTP requests for heartbeat config and result endpoints.
type HeartbeatHandler struct {
	svc *service.HeartbeatService
}

// NewHeartbeatHandler creates a new HeartbeatHandler.
func NewHeartbeatHandler(svc *service.HeartbeatService) *HeartbeatHandler {
	return &HeartbeatHandler{svc: svc}
}

// CreateConfig handles POST /api/v1/devices/{id}/heartbeat-configs
func (h *HeartbeatHandler) CreateConfig(w http.ResponseWriter, r *http.Request) {
	deviceID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || deviceID <= 0 {
		Error(w, http.StatusBadRequest, "invalid device ID")
		return
	}

	var req struct {
		Method          string `json:"method"`
		Target          string `json:"target"`
		IntervalSeconds int64  `json:"interval_seconds"`
		TimeoutSeconds  int64  `json:"timeout_seconds"`
		SnmpCommunity   string `json:"snmp_community"`
		SnmpOid         string `json:"snmp_oid"`
		Enabled         *int64 `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Method == "" {
		Error(w, http.StatusBadRequest, "method is required")
		return
	}
	if req.Target == "" {
		Error(w, http.StatusBadRequest, "target is required")
		return
	}

	validMethods := map[string]bool{"icmp": true, "http": true, "tcp": true, "snmp": true}
	if !validMethods[req.Method] {
		Error(w, http.StatusBadRequest, "method must be one of: icmp, http, tcp, snmp")
		return
	}

	interval := req.IntervalSeconds
	if interval <= 0 {
		interval = 30
	}
	timeout := req.TimeoutSeconds
	if timeout <= 0 {
		timeout = 5
	}
	community := req.SnmpCommunity
	if community == "" {
		community = "public"
	}
	oid := req.SnmpOid
	if oid == "" {
		oid = "1.3.6.1.2.1.1.3.0"
	}
	enabled := int64(1)
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	config, err := h.svc.GetQueries().CreateHeartbeatConfig(r.Context(), db.CreateHeartbeatConfigParams{
		DeviceID:        deviceID,
		Method:          req.Method,
		Target:          req.Target,
		IntervalSeconds: interval,
		TimeoutSeconds:  timeout,
		SnmpCommunity:   community,
		SnmpOid:         oid,
		Enabled:         enabled,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to create heartbeat config")
		return
	}

	Created(w, config)
}

// ListConfigs handles GET /api/v1/devices/{id}/heartbeat-configs
func (h *HeartbeatHandler) ListConfigs(w http.ResponseWriter, r *http.Request) {
	deviceID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || deviceID <= 0 {
		Error(w, http.StatusBadRequest, "invalid device ID")
		return
	}

	configs, err := h.svc.GetQueries().ListHeartbeatConfigsByDevice(r.Context(), deviceID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list heartbeat configs")
		return
	}

	if configs == nil {
		configs = []db.HeartbeatConfig{}
	}

	Success(w, domain.HeartbeatConfigListResponse{
		Configs: configs,
		Total:   len(configs),
	})
}

// UpdateConfig handles PUT /api/v1/heartbeat-configs/{id}
func (h *HeartbeatHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	configID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || configID <= 0 {
		Error(w, http.StatusBadRequest, "invalid config ID")
		return
	}

	// Get existing config first for merge
	existing, err := h.svc.GetQueries().GetHeartbeatConfig(r.Context(), configID)
	if err != nil {
		Error(w, http.StatusNotFound, "heartbeat config not found")
		return
	}

	var req struct {
		Method          *string `json:"method"`
		Target          *string `json:"target"`
		IntervalSeconds *int64  `json:"interval_seconds"`
		TimeoutSeconds  *int64  `json:"timeout_seconds"`
		SnmpCommunity   *string `json:"snmp_community"`
		SnmpOid         *string `json:"snmp_oid"`
		Enabled         *int64  `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	method := existing.Method
	if req.Method != nil {
		validMethods := map[string]bool{"icmp": true, "http": true, "tcp": true, "snmp": true}
		if !validMethods[*req.Method] {
			Error(w, http.StatusBadRequest, "method must be one of: icmp, http, tcp, snmp")
			return
		}
		method = *req.Method
	}

	target := existing.Target
	if req.Target != nil {
		target = *req.Target
	}

	interval := existing.IntervalSeconds
	if req.IntervalSeconds != nil && *req.IntervalSeconds > 0 {
		interval = *req.IntervalSeconds
	}

	timeout := existing.TimeoutSeconds
	if req.TimeoutSeconds != nil && *req.TimeoutSeconds > 0 {
		timeout = *req.TimeoutSeconds
	}

	community := existing.SnmpCommunity
	if req.SnmpCommunity != nil {
		community = *req.SnmpCommunity
	}

	oid := existing.SnmpOid
	if req.SnmpOid != nil {
		oid = *req.SnmpOid
	}

	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	config, err := h.svc.GetQueries().UpdateHeartbeatConfig(r.Context(), db.UpdateHeartbeatConfigParams{
		Method:          method,
		Target:          target,
		IntervalSeconds: interval,
		TimeoutSeconds:  timeout,
		SnmpCommunity:   community,
		SnmpOid:         oid,
		Enabled:         enabled,
		ID:              configID,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to update heartbeat config")
		return
	}

	Success(w, config)
}

// DeleteConfig handles DELETE /api/v1/heartbeat-configs/{id}
func (h *HeartbeatHandler) DeleteConfig(w http.ResponseWriter, r *http.Request) {
	configID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || configID <= 0 {
		Error(w, http.StatusBadRequest, "invalid config ID")
		return
	}

	affected, err := h.svc.GetQueries().DeleteHeartbeatConfig(r.Context(), configID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to delete heartbeat config")
		return
	}
	if affected == 0 {
		Error(w, http.StatusNotFound, "heartbeat config not found")
		return
	}

	Success(w, map[string]string{"message": "heartbeat config deleted"})
}

// ListResults handles GET /api/v1/devices/{id}/heartbeat-results
func (h *HeartbeatHandler) ListResults(w http.ResponseWriter, r *http.Request) {
	deviceID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || deviceID <= 0 {
		Error(w, http.StatusBadRequest, "invalid device ID")
		return
	}

	q := r.URL.Query()
	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)

	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	startDate := q.Get("start_date")
	endDate := q.Get("end_date")

	var startTime, endTime time.Time
	if startDate != "" {
		startTime, _ = time.Parse(time.RFC3339, startDate)
	}
	if endDate != "" {
		endTime, _ = time.Parse(time.RFC3339, endDate)
	}

	results, err := h.svc.GetQueries().ListHeartbeatResultsByDevice(r.Context(), db.ListHeartbeatResultsByDeviceParams{
		DeviceID:    deviceID,
		Column2:     startDate,
		CheckedAt:   startTime,
		Column4:     endDate,
		CheckedAt_2: endTime,
		Limit:       limit,
		Offset:      offset,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list heartbeat results")
		return
	}

	if results == nil {
		results = []db.HeartbeatResult{}
	}

	Success(w, domain.HeartbeatResultListResponse{
		Results: results,
		Total:   len(results),
	})
}

// ListHistory handles GET /api/v1/devices/{id}/heartbeat-history
func (h *HeartbeatHandler) ListHistory(w http.ResponseWriter, r *http.Request) {
	deviceID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || deviceID <= 0 {
		Error(w, http.StatusBadRequest, "invalid device ID")
		return
	}

	q := r.URL.Query()
	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)

	from, err := time.Parse(time.RFC3339, q.Get("from"))
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid or missing 'from' parameter (ISO 8601 required)")
		return
	}

	to, err := time.Parse(time.RFC3339, q.Get("to"))
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid or missing 'to' parameter (ISO 8601 required)")
		return
	}

	if !to.After(from) {
		Error(w, http.StatusBadRequest, "'to' must be after 'from'")
		return
	}

	if to.Sub(from) > 90*24*time.Hour {
		Error(w, http.StatusBadRequest, "date range max 90 days")
		return
	}

	resp, err := h.svc.GetHistory(r.Context(), deviceID, from, to, int32(limit), int32(offset))
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list heartbeat history")
		return
	}

	Success(w, resp)
}

// GetStats handles GET /api/v1/devices/{id}/heartbeat-stats
func (h *HeartbeatHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	deviceID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || deviceID <= 0 {
		Error(w, http.StatusBadRequest, "invalid device ID")
		return
	}

	q := r.URL.Query()
	from, err := time.Parse(time.RFC3339, q.Get("from"))
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid or missing 'from' parameter (ISO 8601 required)")
		return
	}

	to, err := time.Parse(time.RFC3339, q.Get("to"))
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid or missing 'to' parameter (ISO 8601 required)")
		return
	}

	if !to.After(from) {
		Error(w, http.StatusBadRequest, "'to' must be after 'from'")
		return
	}

	if to.Sub(from) > 90*24*time.Hour {
		Error(w, http.StatusBadRequest, "date range max 90 days")
		return
	}

	resp, err := h.svc.GetStats(r.Context(), deviceID, from, to)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to get heartbeat stats")
		return
	}

	Success(w, resp)
}
