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
	"strconv"
	"time"

	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
)

// recordVLANs persists the 802.1Q VLAN tags observed during a scan into the
// vlans table. The sole source today is Q-BRIDGE-MIB (dot1qTpFdbPort), whose
// OID index encodes <VLAN>.<MAC>; the q_bridge_mib probe extracts the tag into
// Evidence.RawData["vlan_tag"]. LLDP/CDP/ARP don't carry a VLAN tag, so on
// networks without a managed switch this is a no-op (correct — there's nothing
// to record).
//
// This is a per-scan finalize step: it scans the alive reports' evidence for
// vlan_tag entries and upserts one vlans row per unique tag (scoped to the
// network). The name/description are left empty — populating those needs a
// separate dot1qVlanStaticTable walk (future work); the tag alone is enough for
// the topology view to group devices by VLAN.
//
// Best-effort: failures are logged, never abort a scan.
func (rn *Runner) recordVLANs(ctx context.Context, networkID sql.NullInt64, reports []scannerv2.HostReport) {
	if !networkID.Valid {
		return
	}
	netID := networkID.Int64

	// Collect unique VLAN tags from Q-BRIDGE-MIB neighbor evidence.
	seen := map[string]bool{}
	for _, rep := range reports {
		if !rep.Alive {
			continue
		}
		for _, e := range rep.Evidence {
			if e.Kind != "neighbor" || e.RawData == nil {
				continue
			}
			tag := e.RawData["vlan_tag"]
			if tag == "" {
				continue
			}
			// Validate it's a real 1-4094 tag (defensive — the probe already
			// checks, but a malformed entry must never reach the DB).
			n, err := strconv.Atoi(tag)
			if err != nil || n < 1 || n > 4094 {
				continue
			}
			seen[tag] = true
		}
	}
	if len(seen) == 0 {
		return
	}

	now := time.Now().UTC()
	netIDPtr := netID // copy to take address
	inserted := 0
	for tag := range seen {
		n, _ := strconv.ParseInt(tag, 10, 64)
		if _, err := rn.queries.UpsertVLAN(ctx, db.UpsertVLANParams{
			VlanTag:     n,
			Name:        strPtr(""),
			Description: strPtr(""),
			NetworkID:   &netIDPtr,
			FirstSeen:   &now,
			LastSeen:    &now,
		}); err != nil {
			rn.logger.Debug("vlans: upsert vlan failed", "tag", tag, "error", err)
			continue
		}
		inserted++
	}
	if inserted > 0 {
		rn.logger.Info("vlans: recorded observed VLANs",
			"network_id", netID, "vlans", inserted)
	}
}
