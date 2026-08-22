-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. You may use, modify, and redistribute it under
-- those terms; see LICENSE for the full text. A commercial license is available
-- for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

-- name: DeleteServiceEvidenceOlderThanBatched :execrows
-- Retention sweep (batched) for service_evidence. Only written when
-- scanner.persist_raw_evidence is on (default off), but can still accumulate
-- heavily: each raw probe observation is a row.
DELETE FROM service_evidence
WHERE rowid IN (
    SELECT rowid FROM service_evidence WHERE service_evidence.observed_at < ? LIMIT ?
);

-- name: InsertServiceEvidence :exec
-- One raw evidence row (scannerv2/store RecordEvidence, #269: moved to
-- sqlc so CI sqlc-verify guards the schema binding). observed_at is bound
-- as RFC3339 text by the caller (scannerv2.DBTime; NEVER time.Time, whose
-- String() form breaks SQLite date(), see #257). The CAST names the bind as
-- text; sqlc names positional cast params ColumnN.
INSERT INTO service_evidence (ip, device_uuid, source, kind, port, protocol, raw_data, confidence, observed_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS TEXT));
