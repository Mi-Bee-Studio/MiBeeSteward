-- name: UpsertScanSnapshot :exec
-- Mark an IP as seen in this scan: insert or reset miss_count to 0 + refresh
-- last_seen_at. Called for every alive host in a scan.
INSERT INTO scan_snapshots (network_id, task_id, ip, mac, miss_count, last_seen_at)
VALUES (?, ?, ?, ?, 0, ?)
ON CONFLICT(network_id, ip) DO UPDATE SET
    task_id = excluded.task_id,
    mac = CASE WHEN excluded.mac != '' THEN excluded.mac ELSE scan_snapshots.mac END,
    miss_count = 0,
    last_seen_at = excluded.last_seen_at;

-- name: ListSnapshotsForNetwork :many
-- All snapshots for a network (the known alive set). Used to compute the set
-- difference: which of these did NOT appear in the current scan, then
-- increment their miss_count (done in Go since the IN-list is dynamic).
SELECT id, network_id, task_id, ip, mac, miss_count, last_seen_at
FROM scan_snapshots
WHERE network_id = ?;

-- name: ListLostSnapshots :many
-- Snapshots whose miss_count crossed the lost threshold, joined to devices
-- to filter to currently-online ones (a device already offline was already
-- declared lost, so do not re-emit). The grace period (miss_count >= threshold)
-- prevents single-scan jitter from flapping a device offline.
SELECT
    s.id AS id, s.network_id AS network_id, s.task_id AS task_id,
    s.ip AS ip, s.mac AS mac, s.miss_count AS miss_count, s.last_seen_at AS last_seen_at,
    d.id AS device_id, d.name AS device_name, d.type AS device_type, d.status AS device_status
FROM scan_snapshots s
JOIN devices d ON d.ip_address = s.ip AND (d.network_id = s.network_id OR d.network_id IS NULL)
WHERE s.network_id = ?
  AND s.miss_count >= ?
  AND d.status = 'online';

-- name: IncrementSnapshotMiss :exec
-- Bump miss_count for ONE snapshot (by id). Called per missing device from Go
-- after computing the set difference.
UPDATE scan_snapshots SET miss_count = miss_count + 1 WHERE id = ?;

-- name: DeleteScanSnapshotsForNetwork :execrows
-- Remove all snapshots for a network (e.g. when a network is deleted).
DELETE FROM scan_snapshots WHERE network_id = ?;

-- NOTE: ListStaleAgentSnapshots is intentionally NOT a sqlc query -- sqlc's
-- SQLite parser truncates this query's trailing bytes when it contains a
-- JOIN on networks + an empty-string literal in the WHERE clause. The query
-- is defined as raw SQL in internal/service/scannerv2/runner/lease_sweeper.go
-- (staleAgentSnapshotsSQL) and executed via dbConn.QueryContext, matching the
-- device_bridge.go pattern for queries sqlc can't handle cleanly.
