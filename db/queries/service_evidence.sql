-- name: DeleteServiceEvidenceOlderThanBatched :execrows
-- Retention sweep (batched) for service_evidence. Only written when
-- scanner.persist_raw_evidence is on (default off), but can still accumulate
-- heavily: each raw probe observation is a row.
DELETE FROM service_evidence
WHERE rowid IN (
    SELECT rowid FROM service_evidence WHERE service_evidence.observed_at < ? LIMIT ?
);
