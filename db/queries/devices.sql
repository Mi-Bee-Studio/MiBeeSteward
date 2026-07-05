-- name: CreateDevice :one
INSERT INTO devices (
    name, type, brand, model, location, purpose, description,
    status, ip_address, mac_address, serial_number,
    purchase_date, warranty_expiry, tags
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, name, type, brand, model, location, purpose, description, status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags, scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports, detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms, created_at, updated_at;

-- name: GetDevice :one
SELECT id, name, type, brand, model, location, purpose, description, status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags, scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports, detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms, created_at, updated_at
FROM devices
WHERE id = ?;

-- name: ListDevices :many
SELECT id, name, type, brand, model, location, purpose, description, status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags, scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports, detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms, created_at, updated_at
FROM devices
WHERE (? = '' OR status = ?)
  AND (? = '' OR type = ?)
ORDER BY id
LIMIT ? OFFSET ?;

-- name: UpdateDevice :one
UPDATE devices
SET name = ?, type = ?, brand = ?, model = ?, location = ?, purpose = ?, description = ?,
    status = ?, ip_address = ?, mac_address = ?, serial_number = ?,
    purchase_date = ?, warranty_expiry = ?, tags = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, name, type, brand, model, location, purpose, description, status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags, scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports, detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms, created_at, updated_at;

-- name: DeleteDevice :execrows
DELETE FROM devices
WHERE id = ?;

-- name: CountByStatus :many
SELECT status, COUNT(*) AS count
FROM devices
GROUP BY status;

-- name: CountDevicesByType :many
SELECT type, COUNT(*) AS count
FROM devices
GROUP BY type;


-- name: CountDevices :one
SELECT COUNT(*)
FROM devices
WHERE (? = '' OR status = ?)
  AND (? = '' OR type = ?);

-- name: UpdateDeviceScanInfo :exec
UPDATE devices
SET scan_source = ?, prometheus_labels = ?, last_scanned_at = ?, last_scan_task_id = ?, open_ports = ?, detected_services = ?, prometheus_url = ?, node_exporter_url = ?, last_scan_rtt_ms = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;

-- name: GetDeviceByIP :one
SELECT id, name, type, brand, model, location, purpose, description, status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags, scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports, detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms, created_at, updated_at
FROM devices
WHERE ip_address = ?
LIMIT 1;

-- name: UpdateDeviceStatus :exec
-- Updates ONLY the status column (and updated_at). Used by the heartbeat
-- service so a status transition doesn't clobber other columns (name, tags,
-- location, …) that may have been edited between the GetDevice read and this
-- write — the full-row UpdateDevice path is racy in that window.
UPDATE devices
SET status = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;
