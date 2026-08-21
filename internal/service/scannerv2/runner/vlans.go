// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, copy, modify, and redistribute it
// under those terms; see LICENSE for the full text. A commercial license is
// available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package runner

import (
	"context"
	"database/sql"
	"strconv"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
)

// recordVLANs persists the 802.1Q VLANs observed during a scan into the vlans
// table. Two evidence sources (#273):
//
//   - kind "vlan" from the q_bridge_mib probe's dot1qVlanStaticName walk: the
//     configured NAME per tag → fills vlans.name (tags with no static entry
//     keep the tag-only row).
//   - kind "neighbor" vlan_tag (from the FDB index): the set of VLANs that
//     actually carry learned MACs.
//
// LLDP/CDP/ARP don't carry a VLAN tag, so on networks without a managed
// switch this is a no-op (correct — there's nothing to record).
//
// After the upserts, a single-VLAN network gets its subnets.vlan_id linked:
// when the scan saw exactly ONE VLAN for the network, that VLAN is by
// definition the one the subnet's broadcast domain rides on. Multi-VLAN
// networks need per-port PVID evidence to disambiguate and stay unlinked.
//
// This is a per-scan finalize step. Best-effort: failures are logged, never
// abort a scan.
func (rn *Runner) recordVLANs(ctx context.Context, networkID sql.NullInt64, reports []scannerv2.HostReport) {
	if !networkID.Valid {
		return
	}
	netID := networkID.Int64

	// Names from the static-table walk (tag → configured name).
	names := map[string]string{}
	// Tags observed carrying traffic (FDB index) — the authoritative set.
	seen := map[string]bool{}
	for _, rep := range reports {
		if !rep.Alive {
			continue
		}
		for _, e := range rep.Evidence {
			if e.RawData == nil {
				continue
			}
			switch e.Kind {
			case "vlan":
				tag := validVLANTag(e.RawData["vlan_tag"])
				if tag == "" {
					continue
				}
				seen[tag] = true
				if name := e.RawData["vlan_name"]; name != "" {
					names[tag] = name
				}
			case "neighbor":
				tag := validVLANTag(e.RawData["vlan_tag"])
				if tag != "" {
					seen[tag] = true
				}
			}
		}
	}
	if len(seen) == 0 {
		return
	}

	now := time.Now().UTC()
	netIDPtr := netID // copy to take address
	inserted := 0
	var lastVLANID int64
	for tag := range seen {
		n, _ := strconv.ParseInt(tag, 10, 64)
		name := names[tag] // "" when the static walk didn't cover this tag
		vlan, err := rn.queries.UpsertVLAN(ctx, db.UpsertVLANParams{
			VlanTag:     n,
			Name:        strPtr(name),
			Description: strPtr(""),
			NetworkID:   &netIDPtr,
			FirstSeen:   &now,
			LastSeen:    &now,
		})
		if err != nil {
			rn.logger.Debug("vlans: upsert vlan failed", "tag", tag, "error", err)
			continue
		}
		lastVLANID = vlan.ID
		inserted++
	}
	if inserted > 0 {
		rn.logger.Info("vlans: recorded observed VLANs",
			"network_id", netID, "vlans", inserted, "named", len(names))
	}

	// Subnet ↔ VLAN link (#273 goal 2): exactly one observed VLAN for this
	// network means the subnet rides on it — record the association.
	if inserted == 1 {
		rn.linkSubnetVLAN(ctx, netID, lastVLANID)
	}
}

// linkSubnetVLAN sets subnets.vlan_id for the network's subnet when it is
// still NULL. Idempotent; multi-VLAN networks never reach here.
func (rn *Runner) linkSubnetVLAN(ctx context.Context, netID, vlanID int64) {
	res, err := rn.dbConn.ExecContext(ctx,
		`UPDATE subnets SET vlan_id = ? WHERE network_id = ? AND vlan_id IS NULL`, vlanID, netID)
	if err != nil {
		rn.logger.Debug("vlans: subnet-vlan link failed", "network_id", netID, "error", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		rn.logger.Info("vlans: linked subnet to VLAN",
			"network_id", netID, "vlan_id", vlanID, "subnets", n)
	}
}

// validVLANTag returns the decimal tag string when s is a real 1-4094 VLAN
// tag, else "". Defensive — the probe already validates, but a malformed
// entry must never reach the DB.
func validVLANTag(s string) string {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 4094 {
		return ""
	}
	return s
}
