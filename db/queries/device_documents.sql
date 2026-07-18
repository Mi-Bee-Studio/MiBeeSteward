-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: LinkDeviceDocument :exec
INSERT INTO device_documents (device_id, document_id)
VALUES (?, ?);

-- name: UnlinkDeviceDocument :execrows
DELETE FROM device_documents
WHERE device_id = ? AND document_id = ?;

-- name: GetDeviceDocuments :many
SELECT d.id, d.title, d.type, d.url, d.file_path, d.file_size, d.mime_type, d.description, d.created_at, d.updated_at
FROM documents d
JOIN device_documents dd ON d.id = dd.document_id
WHERE dd.device_id = ?;

-- name: GetDocumentDevices :many
SELECT dv.id, dv.name, dv.type, dv.brand, dv.model, dv.location, dv.purpose, dv.description, dv.status, dv.ip_address, dv.mac_address, dv.serial_number, dv.purchase_date, dv.warranty_expiry, dv.tags, dv.created_at, dv.updated_at
FROM devices dv
JOIN device_documents dd ON dv.id = dd.device_id
WHERE dd.document_id = ?;
