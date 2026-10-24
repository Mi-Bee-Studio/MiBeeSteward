-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- vantage (#277): which executor produced the row - 'center' or
-- 'agent:{agent_id}'. Mirrors probe_targets.vantage (the plan); results are
-- the per-vantage tracks.

-- name: CreateProbeResult :exec
-- Appends one outcome row per probe execution. checked_at is an RFC3339 UTC
-- string supplied by the caller (NOT CURRENT_TIMESTAMP: the engine stamps the
-- probe start, and string timestamps keep SQLite date() working).
INSERT INTO probe_results (target_id, status, latency_ms, status_code, error_message, tls_version, cert_not_after, cert_trusted, checked_at, vantage)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListProbeResultsByTarget :many
-- Newest-first series for the history view; id DESC breaks RFC3339 ties for
-- same-second runs. Optional vantage filter via the empty-string
-- short-circuit idiom: pass an empty string to get all vantages interleaved,
-- or one vantage value for that executor's track only.
-- CountProbeResultsByTarget MUST mirror this WHERE.
SELECT id, target_id, status, latency_ms, status_code, error_message, tls_version, cert_not_after, cert_trusted, checked_at, vantage
FROM probe_results
WHERE target_id = ? AND (? = '' OR vantage = ?)
ORDER BY checked_at DESC, id DESC
LIMIT ? OFFSET ?;

-- name: CountProbeResultsByTarget :one
SELECT COUNT(*)
FROM probe_results
WHERE target_id = ? AND (? = '' OR vantage = ?);

-- name: LatestProbeResultsPerVantage :many
-- Newest row of each vantage track for one target. Within one vantage rows
-- are inserted strictly in probe order (single writer per track), so MAX(id)
-- is that track's newest regardless of checked_at string ties.
SELECT p.id, p.target_id, p.status, p.latency_ms, p.status_code, p.error_message, p.tls_version, p.cert_not_after, p.cert_trusted, p.checked_at, p.vantage
FROM probe_results p
JOIN (
    SELECT i.vantage, MAX(i.id) AS max_id
    FROM probe_results AS i
    WHERE i.target_id = ?
    GROUP BY i.vantage
) m ON m.max_id = p.id
ORDER BY p.vantage;

-- name: DeleteProbeResultsByTarget :execrows
-- Explicit cascade on target delete (the main DB does not enable the SQLite
-- foreign_keys pragma, so ON DELETE CASCADE never fires).
DELETE FROM probe_results
WHERE target_id = ?;

-- name: DeleteProbeResultsStaleBatched :execrows
-- Retention sweep (batched) - same shape as DeleteHostTLSCertsStaleBatched.
-- cutoff is an RFC3339 UTC string compared lexically (ISO 8601 sorts).
DELETE FROM probe_results
WHERE id IN (
    SELECT sub.id FROM probe_results AS sub WHERE sub.checked_at < ? LIMIT ?
);

-- name: ListProbeResultsSince :many
-- Raw in-window rows for the egress-quality analyzer (#608): aggregation
-- (ok-rate, exact p50) happens in Go over this bounded set - the default
-- 15-minute window holds at most a few thousand rows even on a busy probe
-- table. Oldest-first so percentiles read naturally.
SELECT id, target_id, status, latency_ms, checked_at, vantage
FROM probe_results
WHERE checked_at >= ?
ORDER BY checked_at ASC, id ASC;

-- name: ListProbeQualityBuckets :many
-- Bucketed aggregation for the egress-quality TREND (the days=7/30 history
-- endpoint): one row per (target, vantage, time bucket) over the quality
-- matrix's system targets. bucket_len slices the RFC3339 UTC column - 13 =
-- hour ("2026-10-24T05"), 10 = day ("2026-10-24") - so buckets are
-- wall-clock aligned and lexically sortable. avg_ms counts successes only
-- (a failure's latency is the timeout burn, not network RTT). SQL-side
-- aggregation keeps the stream bounded: a 30-day month is ~200 bucket rows
-- per track, not ~800k raw rows - the read-time trend stays cheap while the
-- raw ListProbeResultsSince path keeps serving the exact-p50 short window.
SELECT pr.target_id AS target_id,
       pr.vantage AS vantage,
       substr(pr.checked_at, 1, sqlc.arg(bucket_len)) AS bucket,
       COUNT(*) AS samples,
       SUM(CASE WHEN pr.status = 'success' THEN 1 ELSE 0 END) AS ok_count,
       AVG(CASE WHEN pr.status = 'success' AND pr.latency_ms > 0 THEN pr.latency_ms END) AS avg_ms
FROM probe_results pr
JOIN probe_targets pt ON pt.id = pr.target_id
WHERE pr.checked_at >= sqlc.arg(cutoff) AND pt.source = 'system' AND pt.enabled = 1
GROUP BY pr.target_id, pr.vantage, bucket
ORDER BY bucket ASC, pr.target_id ASC, pr.vantage ASC;
