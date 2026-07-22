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
	"encoding/json"
	"time"
)

// deriveTopologyEdges materializes device↔device edges into the topology_edges
// table from the raw device_neighbors rows. device_neighbors stores every
// observed adjacency as device→neighbor_mac (the remote end may be an
// unidentified MAC); topology_edges promotes the subset where BOTH endpoints
// are known devices into a graph the topology view can render as solid links.
//
// This is a per-scan finalize step (sister to injectARPTopology): it runs after
// all hosts are persisted, so every MAC observed this scan has a devices row to
// resolve against. It re-derives the full edge set each scan — cheap (tens of
// rows on a home LAN) and idempotent via the UNIQUE(from, to, edge_type)
// upsert, which also refreshes last_seen + raises confidence when a new
// protocol corroborates an existing edge.
//
// Edge semantics by protocol:
//   - LLDP / CDP / Bridge-MIB / Q-BRIDGE-MIB → edge_type "l2" (physical/logical
//     port adjacency, the strongest signal — a switch literally sees the peer)
//   - ARP → edge_type "l3" (same-subnet reachability via the gateway; weaker —
//     it proves co-location, not a direct link)
//
// Best-effort: failures are logged, never abort a scan (same pattern as the
// other finalize steps).
func (rn *Runner) deriveTopologyEdges(ctx context.Context, networkID sql.NullInt64) {
	if !networkID.Valid {
		return // no network scoping — can't partition edges correctly
	}
	netID := networkID.Int64

	// Pull every neighbor edge for this network, resolving the remote MAC to a
	// device id. Only rows where BOTH device_id and the resolved to_device_id
	// are non-null survive into topology_edges (unidentified neighbors stay in
	// device_neighbors only, rendered as dashed lines).
	rows, err := rn.dbConn.QueryContext(ctx, `
		SELECT dn.device_id, dn.neighbor_mac, dn.protocol, dn.local_port, dn.remote_port,
		       d.id AS to_device_id
		FROM device_neighbors dn
		JOIN devices d ON dn.neighbor_mac = d.mac_address
		WHERE dn.network_id = ? AND dn.device_id != d.id`,
		netID)
	if err != nil {
		rn.logger.Warn("topology-edges: query neighbors failed", "error", err)
		return
	}

	type candidate struct {
		fromID, toID        int64
		protocol, localPort string
		remotePort          string
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		var neighborMAC string // unused beyond dedup/log
		if err := rows.Scan(&c.fromID, &neighborMAC, &c.protocol, &c.localPort, &c.remotePort, &c.toID); err != nil {
			continue
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if len(candidates) == 0 {
		return
	}

	// Batch-upsert in a single tx (one writer lock acquisition).
	tx, err := rn.dbConn.BeginTx(ctx, nil)
	if err != nil {
		rn.logger.Warn("topology-edges: begin tx failed", "error", err)
		return
	}
	defer tx.Rollback() //nolint:errcheck

	now := time.Now().UTC()
	inserted := 0
	for _, c := range candidates {
		edgeType, confidence := edgeSemantics(c.protocol)
		meta := edgeMetadata(c.localPort, c.remotePort, c.protocol)
		// Hand-written upsert (not sqlc): sqlc v1.27.0 truncates the final
		// character of ON CONFLICT ... DO UPDATE SET clauses in the generated
		// Go string constant (excluded.last_seen → excluded.last_se), so the
		// generated query is broken at runtime. Same pattern as arp_topology.go
		// and device_neighbors upserts (both also hand-written for control).
		_, err := tx.ExecContext(ctx, `
			INSERT INTO topology_edges (from_device_id, to_device_id, edge_type, via_protocol, confidence, metadata, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(from_device_id, to_device_id, edge_type) DO UPDATE SET
				via_protocol = CASE WHEN excluded.via_protocol != '' THEN excluded.via_protocol ELSE topology_edges.via_protocol END,
				confidence = CASE WHEN excluded.confidence > topology_edges.confidence THEN excluded.confidence ELSE topology_edges.confidence END,
				metadata = CASE WHEN excluded.metadata != '{}' THEN excluded.metadata ELSE topology_edges.metadata END,
				last_seen = excluded.last_seen`,
			c.fromID, c.toID, edgeType, c.protocol, confidence, meta, now, now)
		if err != nil {
			rn.logger.Debug("topology-edges: upsert edge failed",
				"from", c.fromID, "to", c.toID, "protocol", c.protocol, "error", err)
			continue
		}
		inserted++
	}
	if err := tx.Commit(); err != nil {
		rn.logger.Warn("topology-edges: commit failed", "error", err)
		return
	}

	if inserted > 0 {
		rn.logger.Info("topology-edges: derived device↔device edges",
			"network_id", netID, "edges", inserted)
	}
}

// edgeSemantics maps a device_neighbors.protocol to its (edge_type, confidence).
// Switch-sourced protocols (LLDP/CDP/Bridge-MIB) are L2 physical adjacency and
// carry high confidence; ARP is L3 same-subset reachability (weaker — proves the
// two devices share a broadcast domain, not that one is directly behind the
// other).
func edgeSemantics(protocol string) (edgeType string, confidence float64) {
	switch protocol {
	case "LLDP":
		return "l2", 0.85
	case "CDP":
		return "l2", 0.80
	case "Bridge-MIB", "Q-BRIDGE-MIB":
		return "l2", 0.80
	case "ARP":
		return "l3", 0.50
	default:
		return "l2", 0.60 // unknown but presumably L2-adjacent
	}
}

// edgeMetadata builds the JSON metadata blob for an edge, capturing the port
// context (which local port sees which remote port) that the graph view can
// render as edge labels.
func edgeMetadata(localPort, remotePort, protocol string) string {
	m := map[string]string{}
	if localPort != "" {
		m["local_port"] = localPort
	}
	if remotePort != "" {
		m["remote_port"] = remotePort
	}
	if protocol != "" {
		m["protocol"] = protocol
	}
	if len(m) == 0 {
		return "{}"
	}
	b, _ := json.Marshal(m)
	return string(b)
}
