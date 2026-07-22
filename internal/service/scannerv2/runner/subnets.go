// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package runner

import (
	"context"
	"database/sql"
	"time"

	"mibee-steward/internal/db"
)

// recordSubnets persists the subnet(s) observed during a scan into the subnets
// table. The subnet row carries the network's CIDR + the gateway IP (resolved
// from the kernel routing table, the same source injectARPTopology uses) so the
// topology view has a "this is the broadcast domain + its egress" anchor point.
//
// This is a per-scan finalize step: it runs after injectARPTopology (so the
// gateway is already known). The subnet is keyed by (network_id, cidr): the
// first scan inserts, subsequent scans refresh last_seen (and update the
// gateway if the default route changed). vlan_id is left NULL here — VLAN
// assignment requires L2 evidence (Q-BRIDGE-MIB) and is wired separately.
//
// Best-effort: failures are logged, never abort a scan.
func (rn *Runner) recordSubnets(ctx context.Context, networkID sql.NullInt64) {
	if !networkID.Valid {
		return
	}
	netID := networkID.Int64

	net, err := rn.queries.GetNetwork(ctx, netID)
	if err != nil || net.Cidr == nil || *net.Cidr == "" {
		return // no CIDR recorded for this network — nothing to anchor
	}
	cidr := *net.Cidr

	gateway := readDefaultGateway()
	now := time.Now().UTC()

	// Insert-or-refresh. GetSubnetByCIDR decides the path (the base subnets
	// table has no UNIQUE on (network_id, cidr), so we can't rely on ON
	// CONFLICT).
	if existing, err := rn.queries.GetSubnetByCIDR(ctx, db.GetSubnetByCIDRParams{
		NetworkID: netID,
		Cidr:      cidr,
	}); err == nil {
		// Refresh last_seen + gateway (the route may have changed).
		var gwArg any
		if gateway != "" {
			gwArg = gateway
		} else {
			gwArg = nil
		}
		_, _ = rn.dbConn.ExecContext(ctx,
			`UPDATE subnets SET last_seen = ?, gateway = ? WHERE id = ?`,
			now, gwArg, existing.ID)
		return
	}
	// Not present — insert.
	var vlanID *int64        // NULL until Q-BRIDGE-MIB VLAN linkage is wired
	var gatewayPtr *string  // NULL when no default route resolved
	if gateway != "" {
		gatewayPtr = strPtr(gateway)
	}
	_ = rn.queries.UpsertSubnet(ctx, db.UpsertSubnetParams{
		NetworkID: netID,
		Cidr:      cidr,
		VlanID:    vlanID,
		Gateway:   gatewayPtr,
		Metadata:  "{}",
		FirstSeen: &now,
		LastSeen:  &now,
	})
}
