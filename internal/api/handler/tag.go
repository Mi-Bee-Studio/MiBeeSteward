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
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/service/tags"
)

// TagHandler serves the tag dictionary + device-tag assignments (#665).
// Dictionary mutations are admin-only (route gating); assignments ride the
// device write capability.
type TagHandler struct {
	svc *tags.Service
}

func NewTagHandler(svc *tags.Service) *TagHandler {
	return &TagHandler{svc: svc}
}

type tagRequest struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description"`
	SortOrder   int64  `json:"sort_order"`
}

// List handles GET /api/v1/tags (dictionary, any authenticated user — the
// edit modal and filters need it read-only).
func (h *TagHandler) List(w http.ResponseWriter, r *http.Request) {
	items, err := h.svc.List(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list tags")
		return
	}
	Success(w, map[string]any{"tags": items})
}

// Create handles POST /api/v1/tags (admin).
func (h *TagHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req tagRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	tag, err := h.svc.Create(r.Context(), req.Key, req.Name, req.Color, req.Description, req.SortOrder)
	if err != nil {
		switch {
		case errors.Is(err, tags.ErrInvalidKey):
			Error(w, http.StatusBadRequest, "invalid tag key (lowercase slug, 1-40 chars)")
		case errors.Is(err, tags.ErrDuplicateKey):
			Error(w, http.StatusConflict, "tag key already exists")
		default:
			Error(w, http.StatusInternalServerError, "failed to create tag")
		}
		return
	}
	Created(w, tag)
}

// Update handles PUT /api/v1/tags/{id} (admin).
func (h *TagHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid tag id")
		return
	}
	var req tagRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	tag, err := h.svc.Update(r.Context(), id, req.Name, req.Color, req.Description, req.SortOrder)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to update tag")
		return
	}
	Success(w, tag)
}

// Delete handles DELETE /api/v1/tags/{id} (admin). Built-ins are protected.
func (h *TagHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid tag id")
		return
	}
	if err := h.svc.Delete(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, tags.ErrBuiltinProtected):
			Error(w, http.StatusConflict, "built-in tags cannot be deleted")
		case errors.Is(err, tags.ErrTagNotFound):
			Error(w, http.StatusNotFound, "tag not found")
		default:
			Error(w, http.StatusInternalServerError, "failed to delete tag")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListDeviceTags handles GET /api/v1/devices/{id}/tags.
func (h *TagHandler) ListDeviceTags(w http.ResponseWriter, r *http.Request) {
	deviceID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || deviceID <= 0 {
		Error(w, http.StatusBadRequest, "invalid device id")
		return
	}
	items, err := h.svc.ListForDevice(r.Context(), deviceID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list device tags")
		return
	}
	Success(w, map[string]any{"tags": items})
}

// ReplaceDeviceTags handles PUT /api/v1/devices/{id}/tags — the body's
// tag_ids ARE the device's new tag set.
func (h *TagHandler) ReplaceDeviceTags(w http.ResponseWriter, r *http.Request) {
	deviceID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || deviceID <= 0 {
		Error(w, http.StatusBadRequest, "invalid device id")
		return
	}
	var req struct {
		TagIDs []int64 `json:"tag_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.TagIDs) > 50 {
		Error(w, http.StatusBadRequest, "too many tags (max 50)")
		return
	}
	if err := h.svc.ReplaceDeviceTags(r.Context(), deviceID, req.TagIDs); err != nil {
		Error(w, http.StatusInternalServerError, "failed to set device tags")
		return
	}
	Success(w, map[string]any{"ok": true})
}

// BulkAssign handles POST /api/v1/tags/{id}/devices — assign one tag to a
// batch of devices in one call (the "tag every visitor phone" path).
func (h *TagHandler) BulkAssign(w http.ResponseWriter, r *http.Request) {
	tagID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || tagID <= 0 {
		Error(w, http.StatusBadRequest, "invalid tag id")
		return
	}
	var req struct {
		DeviceIDs []int64 `json:"device_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.DeviceIDs) == 0 || len(req.DeviceIDs) > 1000 {
		Error(w, http.StatusBadRequest, "device_ids must contain 1-1000 entries")
		return
	}
	applied, err := h.svc.AddToDevices(r.Context(), tagID, req.DeviceIDs)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to assign tag")
		return
	}
	Success(w, map[string]any{"applied": applied})
}
