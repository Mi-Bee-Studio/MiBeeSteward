package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2/taskservice"
)

// ScannerTaskHandler handles HTTP requests for scan task CRUD and management.
type ScannerTaskHandler struct {
	service *taskservice.Service
}

// NewScannerTaskHandler creates a new ScannerTaskHandler.
func NewScannerTaskHandler(service *taskservice.Service) *ScannerTaskHandler {
	return &ScannerTaskHandler{service: service}
}

// CreateTask handles POST /api/v1/scanner/tasks
func (h *ScannerTaskHandler) CreateTask(w http.ResponseWriter, r *http.Request) {
	var req domain.ScanTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.service.CreateTask(r.Context(), req)
	if err != nil {
		Error(w, http.StatusBadRequest, err.Error())
		return
	}

	Created(w, resp)
}

// ListTasks handles GET /api/v1/scanner/tasks
func (h *ScannerTaskHandler) ListTasks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)

	tasks, total, err := h.service.ListTasks(r.Context(), int(limit), int(offset))
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list scan tasks")
		return
	}

	Success(w, domain.ScanTaskListResponse{
		Tasks: tasks,
		Total: int(total),
	})
}

// GetTask handles GET /api/v1/scanner/tasks/{id}
func (h *ScannerTaskHandler) GetTask(w http.ResponseWriter, r *http.Request) {
	id, err := parseScanID(w, r)
	if err != nil {
		return
	}

	resp, err := h.service.GetTask(r.Context(), id)
	if err != nil {
		if errors.Is(err, taskservice.ErrScanTaskNotFound) {
			Error(w, http.StatusNotFound, "scan task not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get scan task")
		return
	}

	Success(w, resp)
}

// UpdateTask handles PUT /api/v1/scanner/tasks/{id}
func (h *ScannerTaskHandler) UpdateTask(w http.ResponseWriter, r *http.Request) {
	id, err := parseScanID(w, r)
	if err != nil {
		return
	}

	var req domain.UpdateScanTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.service.UpdateTask(r.Context(), id, req)
	if err != nil {
		if errors.Is(err, taskservice.ErrScanTaskNotFound) {
			Error(w, http.StatusNotFound, "scan task not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to update scan task")
		return
	}

	Success(w, resp)
}

// DeleteTask handles DELETE /api/v1/scanner/tasks/{id}
func (h *ScannerTaskHandler) DeleteTask(w http.ResponseWriter, r *http.Request) {
	id, err := parseScanID(w, r)
	if err != nil {
		return
	}

	err = h.service.DeleteTask(r.Context(), id)
	if err != nil {
		if errors.Is(err, taskservice.ErrScanTaskNotFound) {
			Error(w, http.StatusNotFound, "scan task not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to delete scan task")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// TriggerTask handles POST /api/v1/scanner/tasks/{id}/trigger
func (h *ScannerTaskHandler) TriggerTask(w http.ResponseWriter, r *http.Request) {
	id, err := parseScanID(w, r)
	if err != nil {
		return
	}

	resp, err := h.service.TriggerTask(r.Context(), id)
	if err != nil {
		if errors.Is(err, taskservice.ErrScanTaskNotFound) {
			Error(w, http.StatusNotFound, "scan task not found")
			return
		}
		if errors.Is(err, taskservice.ErrScanTaskDisabled) {
			Error(w, http.StatusConflict, "scan task is disabled; enable it before triggering")
			return
		}
		// Surface the real cause (e.g. "scheduler not available",
		// "no job registered for task N") instead of a generic 500 string so
		// operators can diagnose scheduler/engine wiring failures.
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	JSON(w, http.StatusAccepted, resp)
}

// CancelScanTask handles POST /api/v1/scanner/tasks/{id}/cancel
func (h *ScannerTaskHandler) CancelScanTask(w http.ResponseWriter, r *http.Request) {
	id, err := parseScanID(w, r)
	if err != nil {
		return
	}

	err = h.service.CancelTask(r.Context(), id)
	if err != nil {
		if errors.Is(err, taskservice.ErrScanTaskNotFound) {
			Error(w, http.StatusNotFound, "scan task not found")
			return
		}
		if errors.Is(err, taskservice.ErrScanNotRunning) {
			Error(w, http.StatusConflict, "scan is not currently running")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to cancel scan task")
		return
	}

	Success(w, map[string]string{"status": "cancelled"})
}

// GetTaskRuns handles GET /api/v1/scanner/tasks/{id}/runs
func (h *ScannerTaskHandler) GetTaskRuns(w http.ResponseWriter, r *http.Request) {
	id, err := parseScanID(w, r)
	if err != nil {
		return
	}

	q := r.URL.Query()
	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)

	runs, total, err := h.service.GetTaskRuns(r.Context(), int(id), int(limit), int(offset))
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list scan task runs")
		return
	}

	Success(w, domain.ScanRunListResponse{
		Runs:  runs,
		Total: int(total),
	})
}

// GetTaskResults handles GET /api/v1/scanner/tasks/{id}/results
func (h *ScannerTaskHandler) GetTaskResults(w http.ResponseWriter, r *http.Request) {
	id, err := parseScanID(w, r)
	if err != nil {
		return
	}

	q := r.URL.Query()
	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)

	results, total, err := h.service.GetTaskResults(r.Context(), int(id), int(limit), int(offset))
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list scan task results")
		return
	}

	Success(w, domain.ScanResultListResponse{
		Results: results,
		Total:   int(total),
	})
}

// parseScanID extracts and validates the {id} path parameter for scan resources.
func parseScanID(w http.ResponseWriter, r *http.Request) (int64, error) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid ID")
		return 0, err
	}
	return id, nil
}
