// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate. See
// LICENSE-COMMERCIAL.md.

package handler

import (
	"net/http"

	"mibee-steward/internal/netinfo"
)

// GetNetworkInterfaces handles GET /api/v1/system/network-interfaces (#678):
// the center host's own IPv4 interfaces as first-use scan suggestions, so the
// UI can offer "scan my own network" instead of a blank CIDR field. Read-only
// host introspection (see internal/netinfo) — no DB, no service layer needed.
func (h *SettingsHandler) GetNetworkInterfaces(w http.ResponseWriter, _ *http.Request) {
	Success(w, netinfo.Snapshot())
}
