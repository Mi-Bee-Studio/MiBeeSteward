// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not accommodate;
// see LICENSE-COMMERCIAL.md.

package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"mibee-steward/internal/domain"
	identitysvc "mibee-steward/internal/service/identity"
)

// IdentityHandler serves the read-only identity review model (#781).
type IdentityHandler struct {
	svc *identitysvc.Service
}

func NewIdentityHandler(svc *identitysvc.Service) *IdentityHandler {
	return &IdentityHandler{svc: svc}
}

// ListCandidates handles GET /api/v1/identity/candidates. DeviceIDs lets the
// inventory page request badges for one page in a single batch call.
func (h *IdentityHandler) ListCandidates(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, offset, ok := ParsePagination(w, r, 50, 500)
	if !ok {
		return
	}
	filter := identitysvc.CandidateFilter{
		Limit:         int(limit),
		Offset:        int(offset),
		MinConfidence: domain.IdentityConfidence(q.Get("min_confidence")),
	}
	if raw := q.Get("network_id"); raw != "" {
		id, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil || id <= 0 {
			Error(w, http.StatusBadRequest, "invalid network_id")
			return
		}
		filter.NetworkID = &id
	}
	if raw := strings.TrimSpace(q.Get("device_ids")); raw != "" {
		parts := strings.Split(raw, ",")
		if len(parts) > 200 {
			Error(w, http.StatusBadRequest, "device_ids accepts at most 200 ids")
			return
		}
		for _, part := range parts {
			id, parseErr := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
			if parseErr != nil || id <= 0 {
				Error(w, http.StatusBadRequest, "invalid device_ids")
				return
			}
			filter.DeviceIDs = append(filter.DeviceIDs, id)
		}
	}
	out, err := h.svc.Candidates(r.Context(), domain.ScopeFromContext(r.Context()), filter)
	if err != nil {
		if errors.Is(err, identitysvc.ErrInvalidFilter) {
			Error(w, http.StatusBadRequest, err.Error())
			return
		}
		Error(w, http.StatusInternalServerError, "failed to compute identity candidates")
		return
	}
	Success(w, out)
}

// GetDeviceIdentity handles GET /api/v1/devices/{id}/identity.
func (h *IdentityHandler) GetDeviceIdentity(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		Error(w, http.StatusBadRequest, "invalid device id")
		return
	}
	out, err := h.svc.DeviceIdentity(r.Context(), id, domain.ScopeFromContext(r.Context()))
	if err != nil {
		if errors.Is(err, identitysvc.ErrDeviceNotFound) {
			Error(w, http.StatusNotFound, "device not found")
			return
		}
		Error(w, http.StatusInternalServerError, "failed to compute device identity")
		return
	}
	Success(w, out)
}
