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
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/configdiff"
	"mibee-steward/internal/db"
)

// DeviceConfigHandler serves the read side of the versioned running-config
// store (#137) — the Oxidized/RANCID-style config-history view on the device
// detail page. It is read-only: the write path is the background
// configbackup.Service (scheduled SSH pull → diff → device_configs row +
// device_config_changed event). Per the handler/service charter, a read-only
// passthrough handler may use *db.Queries directly.
//
// Note: config_text can contain device secrets (plaintext passwords, SNMP
// communities). It is gated behind the same RequireAuth as the other device
// sub-resources (neighbors/certificates/systems); tightening to admin-only is
// deferred to the RBAC track (#138) so this endpoint stays consistent with its
// siblings.
type DeviceConfigHandler struct {
	queries *db.Queries
}

// NewDeviceConfigHandler constructs the handler. queries is the shared sqlc
// Queries bound to the main DB.
func NewDeviceConfigHandler(queries *db.Queries) *DeviceConfigHandler {
	return &DeviceConfigHandler{queries: queries}
}

// deviceConfigSummary is one row of the version-history list. config_text is
// omitted (it can be large); has_diff signals whether this version changed vs
// the previous one (diff_from_prev != "").
type deviceConfigSummary struct {
	ID         int64  `json:"id"`
	DeviceID   int64  `json:"device_id"`
	ConfigHash string `json:"config_hash"`
	Protocol   string `json:"protocol"`
	HasDiff    bool   `json:"has_diff"`
	FetchedAt  string `json:"fetched_at"`
}

// deviceConfigDetail is the full single-version view: config_text +
// diff_from_prev (the change that introduced this version).
type deviceConfigDetail struct {
	ID           int64  `json:"id"`
	DeviceID     int64  `json:"device_id"`
	ConfigHash   string `json:"config_hash"`
	ConfigText   string `json:"config_text"`
	Protocol     string `json:"protocol"`
	DiffFromPrev string `json:"diff_from_prev"`
	FetchedAt    string `json:"fetched_at"`
}

// deviceConfigVersionRef names one side of a two-version comparison.
type deviceConfigVersionRef struct {
	ID        int64  `json:"id"`
	FetchedAt string `json:"fetched_at"`
}

// deviceConfigDiffResponse is the result of GET .../configs/diff?a=&b=.
type deviceConfigDiffResponse struct {
	A    deviceConfigVersionRef `json:"a"`
	B    deviceConfigVersionRef `json:"b"`
	Diff string                 `json:"diff"` // unified diff; "" when the two versions are identical
}

// List handles GET /api/v1/devices/{id}/configs — the version history for the
// device-detail "Config History" tab. Newest first; metadata only (config_text
// omitted). Returns 200 with an empty items array (not 404) for a device that
// has no captures yet — the frontend renders an empty state.
func (h *DeviceConfigHandler) List(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := parseDeviceConfigDeviceID(w, r)
	if !ok {
		return
	}
	// 404 for a nonexistent device (parity with GET /devices/{id}, #257) —
	// previously this returned 200 + an empty list, hiding typos from API
	// consumers.
	if _, err := h.queries.GetDevice(r.Context(), deviceID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			Error(w, http.StatusNotFound, "device not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to load device")
		return
	}
	limit, offset := parseListPaging(r)
	rows, err := h.queries.ListDeviceConfigs(r.Context(), db.ListDeviceConfigsParams{
		DeviceID: deviceID, Limit: limit, Offset: offset,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list device configs")
		return
	}
	items := make([]deviceConfigSummary, 0, len(rows))
	for _, row := range rows {
		items = append(items, deviceConfigSummary{
			ID:         row.ID,
			DeviceID:   row.DeviceID,
			ConfigHash: row.ConfigHash,
			Protocol:   row.Protocol,
			HasDiff:    row.DiffFromPrev != "",
			FetchedAt:  row.FetchedAt.UTC().Format(time.RFC3339),
		})
	}
	total, err := h.queries.CountDeviceConfigs(r.Context(), deviceID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to count device configs")
		return
	}
	Success(w, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
}

// Get handles GET /api/v1/devices/{id}/configs/{configId} — the full text of one
// version (the detail / "view config" view). A config not belonging to the path
// device returns 404 (IDOR guard: a configId from another device is treated as
// not found, never leaked).
func (h *DeviceConfigHandler) Get(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := parseDeviceConfigDeviceID(w, r)
	if !ok {
		return
	}
	configID, ok := parseDeviceConfigID(w, r)
	if !ok {
		return
	}
	cfg, err := h.loadOwnedConfig(r.Context(), deviceID, configID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			Error(w, http.StatusNotFound, "config version not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to fetch config version")
		return
	}
	Success(w, deviceConfigDetail{
		ID:           cfg.ID,
		DeviceID:     cfg.DeviceID,
		ConfigHash:   cfg.ConfigHash,
		ConfigText:   cfg.ConfigText,
		Protocol:     cfg.Protocol,
		DiffFromPrev: cfg.DiffFromPrev,
		FetchedAt:    cfg.FetchedAt.UTC().Format(time.RFC3339),
	})
}

// Diff handles GET /api/v1/devices/{id}/configs/diff?a={id}&b={id} — a unified
// diff between any two captured versions of the same device. Both versions must
// belong to the path device (else 404). a==b yields an empty diff. The diff is
// computed on demand from the stored config_text (it is not the same as either
// version's diff_from_prev, which only covers that version vs its immediate
// predecessor).
func (h *DeviceConfigHandler) Diff(w http.ResponseWriter, r *http.Request) {
	deviceID, ok := parseDeviceConfigDeviceID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	aID, err := strconv.ParseInt(q.Get("a"), 10, 64)
	if err != nil || aID <= 0 {
		Error(w, http.StatusBadRequest, "invalid or missing 'a' config id")
		return
	}
	bID, err := strconv.ParseInt(q.Get("b"), 10, 64)
	if err != nil || bID <= 0 {
		Error(w, http.StatusBadRequest, "invalid or missing 'b' config id")
		return
	}
	aCfg, err := h.loadOwnedConfig(r.Context(), deviceID, aID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			Error(w, http.StatusNotFound, "config version 'a' not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to fetch config version 'a'")
		return
	}
	bCfg, err := h.loadOwnedConfig(r.Context(), deviceID, bID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			Error(w, http.StatusNotFound, "config version 'b' not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to fetch config version 'b'")
		return
	}
	diff := configdiff.MustDiff(configVersionLabel(aCfg), aCfg.ConfigText, configVersionLabel(bCfg), bCfg.ConfigText)
	Success(w, deviceConfigDiffResponse{
		A:    deviceConfigVersionRef{ID: aCfg.ID, FetchedAt: aCfg.FetchedAt.UTC().Format(time.RFC3339)},
		B:    deviceConfigVersionRef{ID: bCfg.ID, FetchedAt: bCfg.FetchedAt.UTC().Format(time.RFC3339)},
		Diff: diff,
	})
}

// loadOwnedConfig fetches one config version and enforces that it belongs to
// deviceID. A missing row OR a row owned by a different device both surface as
// sql.ErrNoRows so callers map them uniformly to 404 (no cross-device leak).
func (h *DeviceConfigHandler) loadOwnedConfig(ctx context.Context, deviceID, configID int64) (db.DeviceConfig, error) {
	cfg, err := h.queries.GetDeviceConfig(ctx, configID)
	if err != nil {
		return db.DeviceConfig{}, err
	}
	if cfg.DeviceID != deviceID {
		return db.DeviceConfig{}, sql.ErrNoRows
	}
	return cfg, nil
}

// configVersionLabel labels one side of a diff header (the ---/+++ lines).
func configVersionLabel(cfg db.DeviceConfig) string {
	return fmt.Sprintf("config #%d @ %s", cfg.ID, cfg.FetchedAt.UTC().Format(time.RFC3339))
}

// parseDeviceConfigDeviceID extracts and validates the {id} path param (device).
func parseDeviceConfigDeviceID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid device id")
		return 0, false
	}
	return id, true
}

// parseDeviceConfigID extracts and validates the {configId} path param.
func parseDeviceConfigID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "configId"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid config id")
		return 0, false
	}
	return id, true
}
