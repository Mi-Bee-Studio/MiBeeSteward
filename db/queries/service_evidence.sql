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
