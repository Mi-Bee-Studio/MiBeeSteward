-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: CreateScanResult :one
INSERT INTO scan_results (task_id, run_id, ip, alive, rtt_ms, ports, services, snmp_data, prometheus_detected, prometheus_url, node_exporter_detected, node_exporter_url, node_exporter_data)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: ListScanResults :many
SELECT id, task_id, run_id, ip, alive, rtt_ms, ports, services, snmp_data, prometheus_detected, prometheus_url, node_exporter_detected, node_exporter_url, node_exporter_data, scanned_at
FROM scan_results
WHERE (? = 0 OR task_id = ?)
  AND (? = '' OR ip LIKE ?)
  AND (? < 0 OR alive = ?)
ORDER BY scanned_at DESC
LIMIT ? OFFSET ?;

-- name: GetScanResultByIP :one
SELECT id, task_id, run_id, ip, alive, rtt_ms, ports, services, snmp_data, prometheus_detected, prometheus_url, node_exporter_detected, node_exporter_url, node_exporter_data, scanned_at
FROM scan_results
WHERE task_id = ? AND ip = ?
ORDER BY scanned_at DESC
LIMIT 1;

-- name: BatchInsertScanResults :exec
INSERT INTO scan_results (task_id, run_id, ip, alive, rtt_ms, ports, services, snmp_data, prometheus_detected, prometheus_url, node_exporter_detected, node_exporter_url, node_exporter_data)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeleteScanResultsOlderThan :execrows
DELETE FROM scan_results
WHERE scanned_at < datetime('now', '-' || ? || ' days');

-- name: CountScanResults :one
-- The WHERE mirrors ListScanResults (task_id + ip + alive) so the page total
-- reflects active filters. The previous version only counted by task_id, which
-- made the total and pagination wrong whenever ip or alive filters were set.
SELECT COUNT(*)
FROM scan_results
WHERE (? = 0 OR task_id = ?)
  AND (? = '' OR ip LIKE ?)
  AND (? < 0 OR alive = ?);

-- name: ListNodeExporterScanResults :many
SELECT DISTINCT ip, node_exporter_url
FROM scan_results
WHERE node_exporter_detected = 1
  AND node_exporter_url != ''
ORDER BY ip;

-- name: GetScanResult :one
SELECT id, task_id, run_id, ip, alive, rtt_ms, ports, services, snmp_data, prometheus_detected, prometheus_url, node_exporter_detected, node_exporter_url, node_exporter_data, scanned_at
FROM scan_results
WHERE id = ?;

-- name: DeleteScanResultsOlderThanBatched :execrows
-- Retention sweep (batched): deletes up to ? rows older than the cutoff
-- timestamp. The legacy DeleteScanResultsOlderThan takes a days-string and
-- deletes in one shot; this batched cutoff form is what the sweeper uses to
-- avoid a single giant transaction on large result sets.
DELETE FROM scan_results
WHERE rowid IN (
    SELECT rowid FROM scan_results WHERE scan_results.scanned_at < ? LIMIT ?
);
