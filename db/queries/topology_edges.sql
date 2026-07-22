-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. See LICENSE for the full text. A commercial
-- license is available for use cases the AGPL does not accommodate; see
-- LICENSE-COMMERCIAL.md.

-- name: ListTopologyEdgesByNetwork :many
-- All device↔device edges for one network's devices (used by the topology
-- graph). Filters by either endpoint belonging to the network so an edge
-- spanning a known + an external device still appears. network_id <= 0 = all.
SELECT DISTINCT
    te.id, te.from_device_id, te.to_device_id, te.edge_type, te.via_protocol,
    te.confidence, te.metadata, te.first_seen, te.last_seen
FROM topology_edges te
JOIN devices df ON te.from_device_id = df.id
JOIN devices dt ON te.to_device_id = dt.id
WHERE (? <= 0 OR df.network_id = ? OR dt.network_id = ?)
ORDER BY te.edge_type, te.confidence DESC, te.id;

-- name: DeleteStaleTopologyEdges :execrows
-- Retention sweep: remove edges whose last_seen is older than the cutoff.
DELETE FROM topology_edges
WHERE id IN (
    SELECT sub.id FROM topology_edges AS sub WHERE sub.last_seen < ? LIMIT ?
);
