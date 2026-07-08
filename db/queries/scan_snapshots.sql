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

-- name: IncrementSnapshotMisses :execrows
-- Bump miss_count for every snapshot on this network whose ip is NOT in the
-- seen-set (the alive IPs from the scan that just ran). This is the set
-- difference that drives device_lost detection. The placeholders (?, ?, ...)
-- are expanded inline by the caller (not via sqlc params) because IN-lists
-- can't be parameterized directly in sqlite — built in Go as a quoted literal
-- list of IPs. Never interpolates user data directly: the IPs are the
-- scan's own output, validated as IPs before use.
-- NOTE: this query is hand-written SQL executed via dbConn.Exec (not sqlc)
-- because of the dynamic IN-list. Kept here for documentation/discoverability.

-- name: ListLostSnapshots :many
-- Snapshots whose miss_count has crossed the lost threshold, joined to devices
-- to filter to currently-online ones (a device already offline was already
-- declared lost — don't re-emit). The grace period (miss_count >= threshold)
-- prevents single-scan jitter from flapping a device offline.
SELECT s.id, s.network_id, s.task_id, s.ip, s.mac, s.miss_count, s.last_seen_at,
       d.id AS device_id, d.name, d.type, d.status
FROM scan_snapshots s
JOIN devices d ON d.ip_address = s.ip AND (d.network_id = s.network_id OR d.network_id IS NULL)
WHERE s.network_id = ?
  AND s.miss_count >= ?
  AND d.status = 'online'
ORDER BY s.ip;

-- name: DeleteScanSnapshotsForNetwork :execrows
-- Remove all snapshots for a network (e.g. when a network is deleted).
DELETE FROM scan_snapshots WHERE network_id = ?;
