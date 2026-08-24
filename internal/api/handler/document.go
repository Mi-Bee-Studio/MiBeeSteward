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
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
)

// DocumentHandler handles HTTP requests for document endpoints.
type DocumentHandler struct {
	svc       *service.DocumentService
	uploadDir string
	auditRepo *service.AuditRepository
}

// NewDocumentHandler creates a new DocumentHandler.
func NewDocumentHandler(svc *service.DocumentService, uploadDir string, auditRepo *service.AuditRepository) *DocumentHandler {
	return &DocumentHandler{svc: svc, uploadDir: uploadDir, auditRepo: auditRepo}
}

// CreateURL handles POST /api/v1/documents — create a URL-type document.
func (h *DocumentHandler) CreateURL(w http.ResponseWriter, r *http.Request) {
	var req domain.CreateDocumentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.svc.CreateURL(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrTitleRequired) || errors.Is(err, service.ErrURLRequired) {
			Error(w, http.StatusBadRequest, err.Error())
			return
		}
		Error(w, http.StatusInternalServerError, "failed to create document")
		return
	}

	Created(w, resp)
}

// UploadFile handles POST /api/v1/documents/upload — upload a file document.
func (h *DocumentHandler) UploadFile(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form (default 32MB memory, rest goes to temp files)
	maxSize := int64(32 << 20)
	if err := r.ParseMultipartForm(maxSize); err != nil {
		Error(w, http.StatusBadRequest, "failed to parse multipart form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		Error(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	title := r.FormValue("title")
	description := r.FormValue("description")

	resp, err := h.svc.UploadFile(r.Context(), file, header, title, description)
	if err != nil {
		slog.Error("failed to upload file", "error", err)
		// Client-fixable rejections surface as their real reason + status —
		// a blanket 500 hid WHY the file was refused.
		switch {
		case errors.Is(err, service.ErrFileTooLarge):
			Error(w, http.StatusRequestEntityTooLarge, err.Error())
		case errors.Is(err, service.ErrFileTypeNotAllowed):
			Error(w, http.StatusUnsupportedMediaType, err.Error())
		case errors.Is(err, service.ErrFileMismatch), errors.Is(err, service.ErrTitleRequired):
			Error(w, http.StatusBadRequest, err.Error())
		default:
			Error(w, http.StatusInternalServerError, "failed to upload file")
		}
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), service.AuditLog{
			UserID:       &userID,
			Action:       "file.upload",
			ResourceType: "document",
			ResourceID:   strconv.FormatInt(resp.ID, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
			Details:      fmt.Sprintf("filename=%s", header.Filename),
		})
	}

	Created(w, resp)
}

// List handles GET /api/v1/documents — list documents with pagination.
func (h *DocumentHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	offset, _ := strconv.ParseInt(q.Get("offset"), 10, 64)
	search := q.Get("search")

	resp, err := h.svc.List(r.Context(), search, limit, offset)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list documents")
		return
	}

	Success(w, resp)
}

// Get handles GET /api/v1/documents/{id} — get document detail.
func (h *DocumentHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	resp, err := h.svc.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrDocumentNotFound) {
			Error(w, http.StatusNotFound, "document not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get document")
		return
	}

	Success(w, resp)
}

// Download handles GET /api/v1/documents/{id}/download — download a file.
func (h *DocumentHandler) Download(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	filePath, mimeType, err := h.svc.GetFile(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrDocumentNotFound) {
			Error(w, http.StatusNotFound, "document not found")
			return
		}
		if errors.Is(err, service.ErrNotFileDocument) {
			Error(w, http.StatusBadRequest, "document is not a file type")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to get document")
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), service.AuditLog{
			UserID:       &userID,
			Action:       "file.download",
			ResourceType: "document",
			ResourceID:   strconv.FormatInt(id, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	// Validate file path to prevent directory traversal
	absUploadDir, err := filepath.Abs(h.uploadDir)
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid file path")
		return
	}
	absUploadDir += string(filepath.Separator)

	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid file path")
		return
	}

	if !strings.HasPrefix(absFilePath, absUploadDir) {
		Error(w, http.StatusBadRequest, "invalid file path")
		return
	}

	// Pin Content-Type to the upload-validated MIME type. Letting
	// http.ServeFile sniff would serve an HTML-flavored .md as text/html —
	// XSS-same-origin on inline preview. Combined with the global nosniff
	// header, the stored type is authoritative.
	if mimeType != "" {
		w.Header().Set("Content-Type", mimeType)
	}

	// ?inline=1 switches the disposition for embedded previews (PDF iframe,
	// img): browsers refuse to RENDER an attachment inside a navigation
	// context and silently fall back to download. Plain downloads keep
	// attachment (the default), which also stays the safe choice for types
	// a browser might execute if sniffed wrong.
	disposition := "attachment"
	if r.URL.Query().Get("inline") == "1" {
		disposition = "inline"
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("%s; filename=%s", disposition, filepath.Base(filePath)))
	http.ServeFile(w, r, filePath)
}

// Restore handles POST /api/v1/documents/{id}/restore — undo a soft delete
// (the UI's delete-undo toast). Only clears the tombstone; the row and its
// uploaded file were kept.
func (h *DocumentHandler) Restore(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	resp, err := h.svc.Restore(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrDocumentNotFound) {
			Error(w, http.StatusNotFound, "document not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to restore document")
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), service.AuditLog{
			UserID:       &userID,
			Action:       "file.restore",
			ResourceType: "document",
			ResourceID:   strconv.FormatInt(id, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	Success(w, resp)
}

// Update handles PUT /api/v1/documents/{id} — update document.
func (h *DocumentHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	var req domain.UpdateDocumentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.svc.Update(r.Context(), id, req)
	if err != nil {
		if errors.Is(err, service.ErrDocumentNotFound) {
			Error(w, http.StatusNotFound, "document not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to update document")
		return
	}

	Success(w, resp)
}

// Delete handles DELETE /api/v1/documents/{id} — delete document.
func (h *DocumentHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := h.parseID(w, r)
	if err != nil {
		return
	}

	err = h.svc.Delete(r.Context(), id)
	if err != nil {
		if errors.Is(err, service.ErrDocumentNotFound) {
			Error(w, http.StatusNotFound, "document not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to delete document")
		return
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if ok {
		h.auditRepo.Log(r.Context(), service.AuditLog{
			UserID:       &userID,
			Action:       "file.delete",
			ResourceType: "document",
			ResourceID:   strconv.FormatInt(id, 10),
			IPAddress:    r.RemoteAddr,
			UserAgent:    r.UserAgent(),
		})
	}

	Success(w, map[string]string{"message": "document deleted"})
}

// parseID extracts and validates the {id} path parameter.
func (h *DocumentHandler) parseID(w http.ResponseWriter, r *http.Request) (int64, error) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid document ID")
		return 0, err
	}
	return id, nil
}
