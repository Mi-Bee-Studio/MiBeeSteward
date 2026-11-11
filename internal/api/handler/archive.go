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

	"mibee-steward/internal/service/archive"
)

// ArchiveHandler serves the asset-archive API surface (#666): the archive
// list, manual archive/restore, pin + threshold settings, and the dossier
// timeline. All mutations go through the archive service (house layering).
type ArchiveHandler struct {
	svc *archive.Service
}

func NewArchiveHandler(svc *archive.Service) *ArchiveHandler {
	return &ArchiveHandler{svc: svc}
}

func parseIDParam(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, name), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid "+name)
		return 0, false
	}
	return id, true
}

// List handles GET /api/v1/archive — the archived-device page.
func (h *ArchiveHandler) List(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := ParsePagination(w, r, 20, 100)
	if !ok {
		return
	}
	items, total, err := h.svc.ListArchived(r.Context(), limit, offset)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list archive")
		return
	}
	SuccessList(w, "devices", items, total, limit, offset)
}

// Dossier handles GET /api/v1/archive/{id}/dossier — the device's merged
// lifetime timeline (archive events, changes, configs, certs, documents,
// sightings), newest first.
func (h *ArchiveHandler) Dossier(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	entries, err := h.svc.Dossier(r.Context(), id, limit)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to build dossier")
		return
	}
	Success(w, map[string]any{"entries": entries})
}

// ArchiveDevice handles POST /api/v1/devices/{id}/archive — manual archive
// (any scan_source; an online device may be archived too).
func (h *ArchiveHandler) ArchiveDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // body optional
	if err := h.svc.ArchiveDeviceManually(r.Context(), id, req.Reason); err != nil {
		switch {
		case errors.Is(err, archive.ErrAlreadyArchived):
			Error(w, http.StatusConflict, "device is already archived")
		default:
			Error(w, http.StatusInternalServerError, "failed to archive device")
		}
		return
	}
	Success(w, map[string]any{"ok": true})
}

// RestoreDevice handles POST /api/v1/devices/{id}/restore — manual restore;
// {"force":true} clears a force_archive pin first.
func (h *ArchiveHandler) RestoreDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Force bool `json:"force"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // body optional
	if err := h.svc.RestoreDeviceManually(r.Context(), id, req.Force); err != nil {
		switch {
		case errors.Is(err, archive.ErrNotArchived):
			Error(w, http.StatusConflict, "device is not archived")
		case errors.Is(err, archive.ErrPinned):
			Error(w, http.StatusConflict, "device is pinned force_archive; retry with force=true")
		case errors.Is(err, archive.ErrIPConflict):
			Error(w, http.StatusConflict, err.Error())
		default:
			Error(w, http.StatusInternalServerError, "failed to restore device")
		}
		return
	}
	Success(w, map[string]any{"ok": true})
}

// PutArchiveSettings handles PUT /api/v1/devices/{id}/archive-settings —
// pin set/clear + per-device offline-days override.
func (h *ArchiveHandler) PutArchiveSettings(w http.ResponseWriter, r *http.Request) {
	id, ok := parseIDParam(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Pin               *string `json:"pin"`                   // ''|force_archive|force_active; nil = unchanged
		OfflineDaysOverri *int64  `json:"offline_days_override"` // 0/null = clear (follow global)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Pin != nil {
		pin, err := archive.NormalizePin(*req.Pin)
		if err != nil {
			Error(w, http.StatusBadRequest, "invalid pin value")
			return
		}
		if err := h.svc.SetPin(r.Context(), id, pin); err != nil {
			Error(w, http.StatusInternalServerError, "failed to set pin")
			return
		}
	}
	if req.OfflineDaysOverri != nil {
		days := *req.OfflineDaysOverri
		if days < 0 || days > 365 {
			Error(w, http.StatusBadRequest, "offline_days_override must be 0-365")
			return
		}
		if err := h.svc.SetThresholdOverride(r.Context(), id, days); err != nil {
			Error(w, http.StatusInternalServerError, "failed to set threshold override")
			return
		}
	}
	Success(w, map[string]any{"ok": true})
}
