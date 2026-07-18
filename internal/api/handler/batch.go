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
	"net/http"

	"mibee-steward/internal/api/middleware"
	"mibee-steward/internal/service"
)

// BatchHandler handles HTTP requests for batch operations.
type BatchHandler struct {
	svc *service.BatchService
}

// NewBatchHandler creates a new BatchHandler.
func NewBatchHandler(svc *service.BatchService) *BatchHandler {
	return &BatchHandler{svc: svc}
}

// batchIDsRequest represents a request with a list of IDs.
type batchIDsRequest struct {
	IDs []int64 `json:"ids"`
}

// batchUpdateStatusRequest represents a request to update device statuses.
type batchUpdateStatusRequest struct {
	IDs    []int64 `json:"ids"`
	Status string  `json:"status"`
}

// BatchDeleteDevices handles POST /api/v1/devices/batch-delete
func (h *BatchHandler) BatchDeleteDevices(w http.ResponseWriter, r *http.Request) {
	var req batchIDsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.IDs) == 0 {
		Error(w, http.StatusBadRequest, "ids is required and must not be empty")
		return
	}

	for _, id := range req.IDs {
		if id <= 0 {
			Error(w, http.StatusBadRequest, "all IDs must be positive integers")
			return
		}
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if !ok {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	deleted, err := h.svc.DeleteDevices(r.Context(), req.IDs, userID)
	if err != nil {
		if errors.Is(err, service.ErrBatchEmptyIDs) {
			Error(w, http.StatusBadRequest, "no IDs provided")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to delete devices")
		return
	}

	Success(w, map[string]int64{"deleted": deleted})
}

// BatchUpdateDeviceStatus handles POST /api/v1/devices/batch-update-status
func (h *BatchHandler) BatchUpdateDeviceStatus(w http.ResponseWriter, r *http.Request) {
	var req batchUpdateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.IDs) == 0 {
		Error(w, http.StatusBadRequest, "ids is required and must not be empty")
		return
	}

	if req.Status == "" {
		Error(w, http.StatusBadRequest, "status is required")
		return
	}

	for _, id := range req.IDs {
		if id <= 0 {
			Error(w, http.StatusBadRequest, "all IDs must be positive integers")
			return
		}
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if !ok {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	updated, err := h.svc.UpdateDeviceStatuses(r.Context(), req.IDs, req.Status, userID)
	if err != nil {
		if errors.Is(err, service.ErrBatchEmptyIDs) {
			Error(w, http.StatusBadRequest, "no IDs provided")
			return
		}
		if errors.Is(err, service.ErrBatchInvalidStatus) {
			Error(w, http.StatusBadRequest, "invalid device status")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to update device statuses")
		return
	}

	Success(w, map[string]int64{"updated": updated})
}

// BatchDeleteUsers handles POST /api/v1/users/batch-delete
func (h *BatchHandler) BatchDeleteUsers(w http.ResponseWriter, r *http.Request) {
	var req batchIDsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.IDs) == 0 {
		Error(w, http.StatusBadRequest, "ids is required and must not be empty")
		return
	}

	for _, id := range req.IDs {
		if id <= 0 {
			Error(w, http.StatusBadRequest, "all IDs must be positive integers")
			return
		}
	}

	userID, _, ok := middleware.GetUserFromContext(r)
	if !ok {
		Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	deleted, err := h.svc.DeleteUsers(r.Context(), req.IDs, userID)
	if err != nil {
		if errors.Is(err, service.ErrBatchSelfDelete) {
			Error(w, http.StatusBadRequest, "cannot delete yourself")
			return
		}
		if errors.Is(err, service.ErrBatchEmptyIDs) {
			Error(w, http.StatusBadRequest, "no IDs provided")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to delete users")
		return
	}

	Success(w, map[string]int64{"deleted": deleted})
}
