-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later; see LICENSE for the full text. A commercial
-- license is available for use cases the AGPL does not accommodate; see
-- LICENSE-COMMERCIAL.md.

-- name: DeleteProbeTLSCertsByTarget :execrows
-- First half of the delete-then-insert upsert (the table always holds the
-- CURRENT chain of the target). Also the explicit cascade on target delete:
-- the main DB does not enable the SQLite foreign_keys pragma.
DELETE FROM probe_tls_certs
WHERE target_id = ?;

-- name: CreateProbeTLSCert :exec
INSERT INTO probe_tls_certs (target_id, port, cert_index, subject_cn, subject_org, subject, issuer_cn, issuer_org, issuer,
    san_dns, san_ip, san_email, serial, not_before, not_after, sig_algorithm, key_algorithm, key_bits,
    is_ca, self_signed, fingerprint_sha256, pem, tls_version, cipher_suite, trusted, error)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListProbeTLSCertsByTarget :many
SELECT id, target_id, port, cert_index, subject_cn, subject_org, subject, issuer_cn, issuer_org, issuer,
    san_dns, san_ip, san_email, serial, not_before, not_after, sig_algorithm, key_algorithm, key_bits,
    is_ca, self_signed, fingerprint_sha256, pem, tls_version, cipher_suite, trusted, error, updated_at
FROM probe_tls_certs
WHERE target_id = ?
ORDER BY cert_index ASC;
