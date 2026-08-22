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
-- Join through devices on device_uuid so certs follow the device across a DHCP
-- roam (a device's IP is NOT stable, so the old ip-based join stranded the cert
-- rows on the pre-roam IP). Transition rows with empty device_uuid fall back to
-- the IP join. Ordered for stable UI display (port, then chain order).
SELECT c.*
FROM host_tls_certs AS c
JOIN devices AS d ON (
    (d.device_uuid != '' AND c.device_uuid = d.device_uuid)
    OR (c.device_uuid = '' AND c.ip = d.ip_address)
)
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
);

-- name: InsertHostTLSCert :exec
-- One certificate-chain row (cert_index 0 = leaf); the per-(ip, port)
-- DELETE runs first in the same tx. Column list mirrors the store raw
-- insert verbatim; not_before/not_after/updated_at are RFC3339 text.
INSERT INTO host_tls_certs (
    ip, device_uuid, port, cert_index,
    subject_cn, subject_org, subject, issuer_cn, issuer_org, issuer,
    san_dns, san_ip, san_email, serial,
    not_before, not_after,
    sig_algorithm, key_algorithm, key_bits, is_ca, self_signed,
    fingerprint_sha256, pem,
    tls_version, cipher_suite, trusted, error, updated_at
) VALUES (?, ?, ?, ?,  ?, ?, ?, ?, ?, ?,  ?, ?, ?, ?,  CAST(? AS TEXT), CAST(? AS TEXT),  ?, ?, ?, ?, ?,  ?, ?,  ?, ?, ?, ?, CAST(? AS TEXT));

-- name: DeleteHostTLSCertsForIPPort :exec
-- Per-(ip, port) wholesale replace (the delete half of the store
-- RecordTLSCerts, #269): a rotated cert must not linger, but ports NOT in
-- this call keep their rows (a partial scan must not wipe untouched ports).
DELETE FROM host_tls_certs WHERE ip = ? AND port = ?;
