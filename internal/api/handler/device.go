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

// DeviceHandler handles HTTP requests for device endpoints.
type DeviceHandler struct {
	svc *service.DeviceService
}

// NewDeviceHandler creates a new DeviceHandler.
func NewDeviceHandler(svc *service.DeviceService) *DeviceHandler {
	return &DeviceHandler{svc: svc}
}

// Routes returns a Chi router with all device routes registered.
func (h *DeviceHandler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/", h.List)
	r.Get("/stats", h.GetStats)
	r.Get("/{id}", h.Get)
	return r
}

// Create handles POST /api/v1/devices
func (h *DeviceHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req domain.CreateDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		Error(w, http.StatusBadRequest, "device name is required")
		return
	}

	resp, err := h.svc.Create(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidIP) {
			Error(w, http.StatusBadRequest, "invalid IP address format")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to create device")
		return
	}

	Created(w, resp)
}

// Get handles GET /api/v1/devices/{id}
func (h *DeviceHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	resp, err := h.svc.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrDeviceNotFound) {
			Error(w, http.StatusNotFound, "device not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get device")
		return
	}

	Success(w, resp)
}

// List handles GET /api/v1/devices
func (h *DeviceHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)

	filter := domain.DeviceFilter{
		Status: q.Get("status"),
		Type:   q.Get("type"),
		Limit:  limit,
		Offset: offset,
	}

	resp, err := h.svc.List(r.Context(), filter)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list devices")
		return
	}

	Success(w, resp)
}

// Update handles PUT /api/v1/devices/{id}
func (h *DeviceHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	var req domain.UpdateDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.svc.Update(r.Context(), id, req)
	if err != nil {
		if errors.Is(err, service.ErrDeviceNotFound) {
			Error(w, http.StatusNotFound, "device not found")
			return
		}
		if errors.Is(err, service.ErrInvalidIP) {
			Error(w, http.StatusBadRequest, "invalid IP address format")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to update device")
		return
	}

	Success(w, resp)
}

// Delete handles DELETE /api/v1/devices/{id}
func (h *DeviceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	err = h.svc.Delete(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrDeviceNotFound) {
			Error(w, http.StatusNotFound, "device not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to delete device")
		return
	}

	Success(w, map[string]string{"message": "device deleted"})
}

// GetStats handles GET /api/v1/devices/stats
func (h *DeviceHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	resp, err := h.svc.GetStats(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to get device stats")
		return
	}

	Success(w, resp)
}

// parseID extracts and validates the {id} path parameter.
func (h *DeviceHandler) parseID(w http.ResponseWriter, r *http.Request) (int64, error) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid device ID")
		return 0, err
	}
	return id, nil
}
