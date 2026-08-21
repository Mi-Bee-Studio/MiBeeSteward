-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later; see LICENSE for the full text. A commercial
-- license is available for use cases the AGPL does not accommodate; see
-- LICENSE-COMMERCIAL.md.

-- name: CreateProbeResult :exec
-- Appends one outcome row per probe execution. checked_at is an RFC3339 UTC
-- string supplied by the caller (NOT CURRENT_TIMESTAMP: the engine stamps the
-- probe start, and string timestamps keep SQLite date() working).
INSERT INTO probe_results (target_id, status, latency_ms, status_code, error_message, tls_version, cert_not_after, cert_trusted, checked_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListProbeResultsByTarget :many
-- Newest-first series for the history view; id DESC breaks RFC3339 ties for
-- same-second runs.
SELECT id, target_id, status, latency_ms, status_code, error_message, tls_version, cert_not_after, cert_trusted, checked_at
FROM probe_results
WHERE target_id = ?
ORDER BY checked_at DESC, id DESC
LIMIT ? OFFSET ?;

-- name: CountProbeResultsByTarget :one
SELECT COUNT(*)
FROM probe_results
WHERE target_id = ?;

-- name: DeleteProbeResultsByTarget :execrows
-- Explicit cascade on target delete (the main DB does not enable the SQLite
-- foreign_keys pragma, so ON DELETE CASCADE never fires).
DELETE FROM probe_results
WHERE target_id = ?;

-- name: DeleteProbeResultsStaleBatched :execrows
-- Retention sweep (batched) - same shape as DeleteHostTLSCertsStaleBatched.
-- cutoff is an RFC3339 UTC string compared lexically (ISO 8601 sorts).
DELETE FROM probe_results
WHERE id IN (
    SELECT sub.id FROM probe_results AS sub WHERE sub.checked_at < ? LIMIT ?
);
