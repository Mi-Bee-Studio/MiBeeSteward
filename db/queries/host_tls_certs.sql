-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: ListTLSCertsByIP :many
SELECT * FROM host_tls_certs
WHERE ip = ?
ORDER BY port ASC, cert_index ASC;

-- name: ListTLSCertsByDeviceID :many
-- Join through devices (composite-unique on (ip_address, network_id) means a
-- device's IP is its cert lookup key). Includes certs from every port on the
-- device, ordered for stable UI display (port, then chain order).
SELECT c.*
FROM host_tls_certs AS c
JOIN devices AS d ON d.ip_address = c.ip
WHERE d.id = ?
ORDER BY c.port ASC, c.cert_index ASC;

-- name: DeleteHostTLSCertsStaleBatched :execrows
-- Retention sweep (batched) for host_tls_certs. Mirrors the host_services
-- retention pattern: rows for hosts that have gone silent are never refreshed
-- and linger, so this removes rows whose updated_at is older than the cutoff,
-- in batches to avoid holding the write lock on large tables.
DELETE FROM host_tls_certs
WHERE id IN (
    SELECT sub.id FROM host_tls_certs AS sub WHERE sub.updated_at < ? LIMIT ?
)
