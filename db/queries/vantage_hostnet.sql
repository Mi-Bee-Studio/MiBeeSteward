-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- Per-vantage local network facts (#746): the agent-rs HostNet sampler
-- reports interface counters, the default-route fingerprint and a DNS
-- resolution sample; quality attribution reads the recent window to answer
-- "did THIS vantage's own network degrade". Append-only series.

-- name: InsertVantageHostnet :exec
-- Appends one sampler row. checked_at is an RFC3339 UTC string supplied by
-- the caller (agent clock), mirroring probe_results.checked_at semantics.
INSERT INTO vantage_hostnet (vantage, checked_at, iface_stats, default_route, dns_ms, note)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ListVantageHostnetByVantage :many
-- Newest-first series for one vantage, bounded. Oldest rows fall out via the
-- retention sweep; attribution only needs the newest handful, history views
-- cap the page.
SELECT id, vantage, checked_at, iface_stats, default_route, dns_ms, note
FROM vantage_hostnet
WHERE vantage = ?
ORDER BY checked_at DESC, id DESC
LIMIT ?;

-- name: LatestVantageHostnet :many
-- Newest row of each vantage (fleet summary cards). Single writer per
-- vantage track, so MAX(id) is that track's newest regardless of string ties.
SELECT h.id, h.vantage, h.checked_at, h.iface_stats, h.default_route, h.dns_ms, h.note
FROM vantage_hostnet h
JOIN (
    SELECT i.vantage, MAX(i.id) AS max_id
    FROM vantage_hostnet AS i
    GROUP BY i.vantage
) m ON m.max_id = h.id
ORDER BY h.vantage;

-- name: DeleteVantageHostnetStaleBatched :execrows
-- Retention sweep (batched), same shape as DeleteProbeResultsStaleBatched.
-- cutoff is an RFC3339 UTC string compared lexically (ISO 8601 sorts).
DELETE FROM vantage_hostnet
WHERE id IN (
    SELECT sub.id FROM vantage_hostnet AS sub WHERE sub.checked_at < ? LIMIT ?
);
