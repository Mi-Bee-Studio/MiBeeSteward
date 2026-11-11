// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package handler

import (
	"net/http"

	"mibee-steward/internal/service/probetarget"
)

// AutogenHandler exposes on-demand autogen actions for the web (设置 → 拨测
// and the probes page's LAN empty state): run one reconcile sweep now
// instead of waiting for the periodic tick.
type AutogenHandler struct {
	svc *probetarget.AutogenService
}

func NewAutogenHandler(svc *probetarget.AutogenService) *AutogenHandler {
	return &AutogenHandler{svc: svc}
}

// SweepNow handles POST /api/v1/probe-targets/autogen-sweep. The sweep reads
// the effective policy (overlay ?? config) at run time, so an OFF switch
// simply parks the auto population — the response still reports what
// happened, and the UI surfaces it.
func (h *AutogenHandler) SweepNow(w http.ResponseWriter, r *http.Request) {
	created, enabled, disabled, err := h.svc.Sweep(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	Success(w, map[string]any{
		"created":  created,
		"enabled":  enabled,
		"disabled": disabled,
	})
}
