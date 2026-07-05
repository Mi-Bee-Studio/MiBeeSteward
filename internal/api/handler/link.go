package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/db"
	"mibee-steward/internal/repository"
)

// LinkHandler handles device-document linking endpoints.
type LinkHandler struct {
	queries   *db.Queries
	auditRepo *repository.AuditRepository // may be nil → auditing skipped
}

// NewLinkHandler creates a new LinkHandler. auditRepo is optional; when set,
// link/unlink actions are recorded in the audit log for parity with other admin
// write operations.
func NewLinkHandler(dbConn db.DBTX, auditRepo *repository.AuditRepository) *LinkHandler {
	return &LinkHandler{queries: db.New(dbConn), auditRepo: auditRepo}
}

// LinkDocument handles POST /api/v1/devices/{id}/documents
func (h *LinkHandler) LinkDocument(w http.ResponseWriter, r *http.Request) {
	deviceID, err := parsePathID(w, r, "id")
	if err != nil {
		return
	}

	var req struct {
		DocumentID int64 `json:"document_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DocumentID <= 0 {
		Error(w, http.StatusBadRequest, "document_id is required")
		return
	}

	err = h.queries.LinkDeviceDocument(r.Context(), db.LinkDeviceDocumentParams{
		DeviceID:   deviceID,
		DocumentID: req.DocumentID,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to link document to device")
		return
	}

	h.auditLink(r, "admin.document.link", deviceID, req.DocumentID)
	Success(w, map[string]string{"message": "document linked to device"})
}

// UnlinkDocument handles DELETE /api/v1/devices/{id}/documents/{docId}
func (h *LinkHandler) UnlinkDocument(w http.ResponseWriter, r *http.Request) {
	deviceID, err := parsePathID(w, r, "id")
	if err != nil {
		return
	}

	docID, err := parsePathID(w, r, "docId")
	if err != nil {
		return
	}

	rowsAffected, err := h.queries.UnlinkDeviceDocument(r.Context(), db.UnlinkDeviceDocumentParams{
		DeviceID:   deviceID,
		DocumentID: docID,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to unlink document from device")
		return
	}
	if rowsAffected == 0 {
		Error(w, http.StatusNotFound, "link not found")
		return
	}

	h.auditLink(r, "admin.document.unlink", deviceID, docID)
	Success(w, map[string]string{"message": "document unlinked from device"})
}

// auditLink records a device↔document link/unlink in the audit log. No-op when
// the handler has no audit repo (keeps the constructor backwards-compatible).
func (h *LinkHandler) auditLink(r *http.Request, action string, deviceID, docID int64) {
	if h.auditRepo == nil {
		return
	}
	userID, _, ok := middleware.GetUserFromContext(r)
	if !ok {
		return
	}
	// Log is best-effort and returns nothing; a write failure is logged inside.
	h.auditRepo.Log(r.Context(), repository.AuditLog{
		UserID:       &userID,
		Action:       action,
		ResourceType: "device",
		ResourceID:   strconv.FormatInt(deviceID, 10),
		IPAddress:    r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		Details:      fmt.Sprintf("document_id=%d", docID),
	})
}

// GetDeviceDocuments handles GET /api/v1/devices/{id}/documents
func (h *LinkHandler) GetDeviceDocuments(w http.ResponseWriter, r *http.Request) {
	deviceID, err := parsePathID(w, r, "id")
	if err != nil {
		return
	}

	docs, err := h.queries.GetDeviceDocuments(r.Context(), deviceID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to get device documents")
		return
	}

	Success(w, docs)
}

// GetDocumentDevices handles GET /api/v1/documents/{id}/devices
func (h *LinkHandler) GetDocumentDevices(w http.ResponseWriter, r *http.Request) {
	docID, err := parsePathID(w, r, "id")
	if err != nil {
		return
	}

	devices, err := h.queries.GetDocumentDevices(r.Context(), docID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to get document devices")
		return
	}

	Success(w, devices)
}

// parsePathID extracts and validates a path parameter as int64.
func parsePathID(w http.ResponseWriter, r *http.Request, param string) (int64, error) {
	idStr := chi.URLParam(r, param)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid ID: "+param)
		return 0, errors.New("invalid ID")
	}
	return id, nil
}
