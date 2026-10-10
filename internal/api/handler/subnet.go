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
	"net/http"
	"strconv"

	"mibee-steward/internal/db"
	"mibee-steward/internal/domain"
)

// SubnetHandler serves the read-only subnets view (#503). The table is
// populated by every scan finalize (runner/subnets.go: the network's CIDR,
// the default gateway from the route table, VLAN linkage when unambiguous).
type SubnetHandler struct {
	queries *db.Queries
}

func NewSubnetHandler(queries *db.Queries) *SubnetHandler {
	return &SubnetHandler{queries: queries}
}

// List handles GET /api/v1/subnets. Optional ?network_id= filters to one
// network (0/absent/unparsable = all, the same lenient contract as the
// topology graph). Non-global scopes see only their allowed networks.
func (h *SubnetHandler) List(w http.ResponseWriter, r *http.Request) {
	networkID, _ := strconv.ParseInt(r.URL.Query().Get("network_id"), 10, 64)
	subnets, err := h.queries.ListSubnets(r.Context(), db.ListSubnetsParams{
		Column1:   networkID,
		NetworkID: networkID,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to list subnets")
		return
	}

	scope := domain.ScopeFromContext(r.Context())
	if !scope.IsGlobal() && networkID == 0 {
		allowed := make(map[int64]bool, len(scope.NetworkIDs))
		for _, id := range scope.NetworkIDs {
			allowed[id] = true
		}
		scoped := make([]db.Subnet, 0, len(subnets))
		for _, s := range subnets {
			if allowed[s.NetworkID] {
				scoped = append(scoped, s)
			}
		}
		subnets = scoped
	}

	Success(w, map[string]any{"subnets": subnets, "total": len(subnets)})
}
