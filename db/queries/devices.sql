-- name: CreateDevice :one
INSERT INTO devices (
    name, type, brand, model, location, purpose, description,
    status, ip_address, mac_address, serial_number,
    purchase_date, warranty_expiry, tags, user_attributes
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, name, type, brand, model, location, purpose, description, status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags, scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports, detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms, scan_attributes, user_attributes, scan_vendor, scan_mac, scan_os, scan_hostname, created_at, updated_at;

-- name: GetDevice :one
SELECT id, name, type, brand, model, location, purpose, description, status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags, scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports, detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms, scan_attributes, user_attributes, scan_vendor, scan_mac, scan_os, scan_hostname, created_at, updated_at
FROM devices
WHERE id = ?;

-- name: ListDevices :many
SELECT id, name, type, brand, model, location, purpose, description, status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags, scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports, detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms, scan_attributes, user_attributes, scan_vendor, scan_mac, scan_os, scan_hostname, created_at, updated_at
FROM devices
WHERE (? = '' OR status = ?)
  AND (? = '' OR type = ?)
ORDER BY id
LIMIT ? OFFSET ?;

-- name: UpdateDevice :one
-- Note: scan_attributes is engine-owned and intentionally NOT updated here.
-- user_attributes is updated via UpdateUserAttributes so the full-row update
-- can't race the user-edit path.
UPDATE devices
SET name = ?, type = ?, brand = ?, model = ?, location = ?, purpose = ?, description = ?,
    status = ?, ip_address = ?, mac_address = ?, serial_number = ?,
    purchase_date = ?, warranty_expiry = ?, tags = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING id, name, type, brand, model, location, purpose, description, status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags, scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports, detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms, scan_attributes, user_attributes, scan_vendor, scan_mac, scan_os, scan_hostname, created_at, updated_at;

-- name: UpdateUserAttributes :exec
UPDATE devices SET user_attributes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

-- name: UpdateScanAttributes :exec
-- Engine-only: replaces the full scan_attributes document. Device bridge and
-- store/sqlite call this with the freshly-marshalled JSON after a scan run.
UPDATE devices SET scan_attributes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;

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
SELECT id, name, type, brand, model, location, purpose, description, status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags, scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports, detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms, scan_attributes, user_attributes, scan_vendor, scan_mac, scan_os, scan_hostname, created_at, updated_at
FROM devices
WHERE ip_address = ?
LIMIT 1;

-- name: GetDeviceByMAC :one
-- Looks up by normalized scan MAC. Uses json_extract so the query works on
-- both fresh installs (which have the scan_mac generated column) and upgraded
-- DBs (which have an expression index on json_extract instead). The expression
-- index idx_devices_scan_mac_expr covers this WHERE clause on either shape.
SELECT id, name, type, brand, model, location, purpose, description, status, ip_address, mac_address, serial_number, purchase_date, warranty_expiry, tags, scan_source, prometheus_labels, last_scanned_at, last_scan_task_id, open_ports, detected_services, prometheus_url, node_exporter_url, last_scan_rtt_ms, scan_attributes, user_attributes, scan_vendor, scan_mac, scan_os, scan_hostname, created_at, updated_at
FROM devices
WHERE json_extract(scan_attributes, '$.mac') = ?
LIMIT 1;

-- name: UpdateDeviceStatus :exec
-- Updates ONLY the status column (and updated_at). Used by the heartbeat
-- service so a status transition doesn't clobber other columns (name, tags,
-- location, …) that may have been edited between the GetDevice read and this
-- write — the full-row UpdateDevice path is racy in that window.
UPDATE devices
SET status = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;
