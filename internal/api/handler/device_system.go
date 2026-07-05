package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
)

// DeviceSystemHandler handles HTTP requests for device system endpoints.
type DeviceSystemHandler struct {
	svc *service.DeviceSystemService
}

// NewDeviceSystemHandler creates a new DeviceSystemHandler.
func NewDeviceSystemHandler(svc *service.DeviceSystemService) *DeviceSystemHandler {
	return &DeviceSystemHandler{svc: svc}
}

// Create handles POST /api/v1/devices/{id}/systems
func (h *DeviceSystemHandler) Create(w http.ResponseWriter, r *http.Request) {
	deviceID, err := h.parseDeviceID(w, r)
	if err != nil {
		return
	}

	var req domain.CreateDeviceSystemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.svc.Create(r.Context(), deviceID, req)
	if err != nil {
		if errors.Is(err, service.ErrSystemNameRequired) {
			Error(w, http.StatusBadRequest, "system name is required")
			return
		}
		if errors.Is(err, service.ErrInvalidEntryURL) {
			Error(w, http.StatusBadRequest, "invalid entry URL")
			return
		}
		if errors.Is(err, service.ErrInvalidMetricsURL) {
			Error(w, http.StatusBadRequest, "invalid metrics URL")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to create device system")
		return
	}

	Created(w, resp)
}

// Get handles GET /api/v1/devices/{id}/systems/{systemId}
func (h *DeviceSystemHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseSystemID(w, r)
	if err != nil {
		return
	}

	resp, err := h.svc.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrDeviceSystemNotFound) {
			Error(w, http.StatusNotFound, "device system not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get device system")
		return
	}

	Success(w, resp)
}

// ListByDevice handles GET /api/v1/devices/{id}/systems
func (h *DeviceSystemHandler) ListByDevice(w http.ResponseWriter, r *http.Request) {
	deviceID, err := h.parseDeviceID(w, r)
	if err != nil {
		return
	}

	q := r.URL.Query()
	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)

	filter := domain.DeviceSystemFilter{
		Category: q.Get("category"),
		Limit:    limit,
		Offset:   offset,
	}

	resp, err := h.svc.ListByDevice(r.Context(), deviceID, filter)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list device systems")
		return
	}

	Success(w, resp)
}

// Update handles PUT /api/v1/devices/{id}/systems/{systemId}
func (h *DeviceSystemHandler) Update(w http.ResponseWriter, r *http.Request) {
	_, err := h.parseDeviceID(w, r)
	if err != nil {
		return
	}

	id, err := h.parseSystemID(w, r)
	if err != nil {
		return
	}

	var req domain.UpdateDeviceSystemRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.svc.Update(r.Context(), id, req)
	if err != nil {
		if errors.Is(err, service.ErrDeviceSystemNotFound) {
			Error(w, http.StatusNotFound, "device system not found")
			return
		}
		if errors.Is(err, service.ErrInvalidEntryURL) {
			Error(w, http.StatusBadRequest, "invalid entry URL")
			return
		}
		if errors.Is(err, service.ErrInvalidMetricsURL) {
			Error(w, http.StatusBadRequest, "invalid metrics URL")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to update device system")
		return
	}

	Success(w, resp)
}

// Delete handles DELETE /api/v1/devices/{id}/systems/{systemId}
func (h *DeviceSystemHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseSystemID(w, r)
	if err != nil {
		return
	}

	err = h.svc.Delete(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrDeviceSystemNotFound) {
			Error(w, http.StatusNotFound, "device system not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to delete device system")
		return
	}

	Success(w, map[string]string{"message": "device system deleted"})
}

// parseDeviceID extracts and validates the {id} path parameter (device ID).
func (h *DeviceSystemHandler) parseDeviceID(w http.ResponseWriter, r *http.Request) (int64, error) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid device ID")
		return 0, err
	}
	return id, nil
}

// parseSystemID extracts and validates the {systemId} path parameter.
func (h *DeviceSystemHandler) parseSystemID(w http.ResponseWriter, r *http.Request) (int64, error) {
	idStr := chi.URLParam(r, "systemId")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid system ID")
		return 0, err
	}
	return id, nil
}
