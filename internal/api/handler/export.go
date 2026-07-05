package handler

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"mibee-steward/internal/service"
)

// ExportHandler handles data export endpoints.
type ExportHandler struct {
	svc *service.ExportService
}

// NewExportHandler creates a new ExportHandler.
func NewExportHandler(svc *service.ExportService) *ExportHandler {
	return &ExportHandler{svc: svc}
}

// ExportDevices handles GET /api/v1/devices/export?format=csv
func (h *ExportHandler) ExportDevices(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		Error(w, http.StatusBadRequest, "unsupported export format, use csv or json")
		return
	}

	contentType, filename := exportHeaders(format, "devices")

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", filename)

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	if err := h.svc.Devices(r.Context(), format, w); err != nil {
		http.Error(w, "export failed", http.StatusInternalServerError)
	}
}

// ExportHeartbeatResults handles GET /api/v1/devices/{id}/heartbeat-results/export?format=csv
func (h *ExportHandler) ExportHeartbeatResults(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid device ID")
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		Error(w, http.StatusBadRequest, "unsupported export format, use csv or json")
		return
	}

	contentType, filename := exportHeaders(format, "heartbeat-results")

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", filename)

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	if err := h.svc.HeartbeatResults(r.Context(), id, format, w); err != nil {
		http.Error(w, "export failed", http.StatusInternalServerError)
	}
}

// ExportAuditLogs handles GET /api/v1/audit-logs/export?format=csv
func (h *ExportHandler) ExportAuditLogs(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		Error(w, http.StatusBadRequest, "unsupported export format, use csv or json")
		return
	}

	contentType, filename := exportHeaders(format, "audit-logs")

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", filename)

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	if err := h.svc.AuditLogs(r.Context(), format, w); err != nil {
		http.Error(w, "export failed", http.StatusInternalServerError)
	}
}

// exportHeaders returns Content-Type and Content-Disposition for the given format.
func exportHeaders(format, baseName string) (contentType, contentDisposition string) {
	if format == "json" {
		return "application/json; charset=utf-8",
			`attachment; filename="` + baseName + `.json"`
	}
	return "text/csv; charset=utf-8",
		`attachment; filename="` + baseName + `.csv"`
}
