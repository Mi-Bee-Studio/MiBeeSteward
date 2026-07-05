-- name: CreateScanResult :one
INSERT INTO scan_results (task_id, run_id, ip, alive, rtt_ms, ports, services, snmp_data, prometheus_detected, prometheus_url, node_exporter_detected, node_exporter_url, node_exporter_data)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: ListScanResults :many
SELECT id, task_id, run_id, ip, alive, rtt_ms, ports, services, snmp_data, prometheus_detected, prometheus_url, node_exporter_detected, node_exporter_url, node_exporter_data, scanned_at
FROM scan_results
WHERE (? = 0 OR task_id = ?)
  AND (? = '' OR ip LIKE ?)
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
SELECT COUNT(*)
FROM scan_results
WHERE (? = 0 OR task_id = ?);

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
