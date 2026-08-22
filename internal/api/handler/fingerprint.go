// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/service"
)

// FingerprintHandler exposes the fingerprint coverage report + rule-draft
// generation (#282). Read-only analytics over device scan_attributes and
// collected evidence; the draft endpoint POSTs but persists nothing — it is
// a pure computation returning YAML text.
type FingerprintHandler struct {
	svc *service.FingerprintReportService
}

func NewFingerprintHandler(svc *service.FingerprintReportService) *FingerprintHandler {
	return &FingerprintHandler{svc: svc}
}

// Coverage handles GET /api/v1/fingerprints/coverage — identification-tier
// stats + the unidentified-device list with feature groupings.
func (h *FingerprintHandler) Coverage(w http.ResponseWriter, r *http.Request) {
	cov, err := h.svc.Coverage(r.Context(), domain.ScopeFromContext(r.Context()))
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	Success(w, cov)
}

// RuleDraft handles POST /api/v1/devices/{uuid}/fingerprint-draft — returns
// text/yaml body generated (and compile-validated) from the device's stored
// evidence. Text (not JSON) so the UI can offer it as a file download
// directly.
func (h *FingerprintHandler) RuleDraft(w http.ResponseWriter, r *http.Request) {
	uuid := chi.URLParam(r, "uuid")
	if uuid == "" {
		Error(w, http.StatusBadRequest, "device uuid is required")
		return
	}
	draft, err := h.svc.RuleDraft(r.Context(), uuid, domain.ScopeFromContext(r.Context()))
	if err != nil {
		Error(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(draft))
}
