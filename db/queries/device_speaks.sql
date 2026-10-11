-- name: DeleteDeviceSpeaksStaleBatched :execrows
DELETE FROM device_speaks_with
WHERE id IN (
    SELECT sub.id FROM device_speaks_with AS sub WHERE sub.last_seen < ? LIMIT ?
);

-- name: ListDeviceSpeaks :many
SELECT ds.id, ds.device_id, ds.peer_ip, ds.bytes_out, ds.bytes_in, ds.first_seen, ds.last_seen,
       ds.peer_device_id,
       pd.name AS peer_name,
       pd.ip_address AS peer_device_ip
FROM device_speaks_with ds
LEFT JOIN devices pd ON ds.peer_device_id = pd.id
WHERE ds.device_id = ?
ORDER BY (ds.bytes_out + ds.bytes_in) DESC
LIMIT ?;

-- name: ListSpeaksEdges :many
SELECT ds.device_id, ds.peer_device_id, ds.bytes_out + ds.bytes_in AS total_bytes,
       ds.first_seen, ds.last_seen
FROM device_speaks_with ds
WHERE ds.peer_device_id IS NOT NULL
  AND ds.device_id != ds.peer_device_id
  AND (? <= 0 OR ds.device_id IN (
      SELECT d.id FROM devices d WHERE d.network_id = ?
  ));
