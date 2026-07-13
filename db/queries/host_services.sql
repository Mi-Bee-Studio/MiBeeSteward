-- name: DeleteHostServicesStaleBatched :execrows
-- Retention sweep (batched) for host_services. host_services is upserted on
-- (ip, service, port), so it does not append per-scan — but rows for hosts
-- that have gone silent are never refreshed and linger. This removes rows
-- whose updated_at is older than the cutoff, in batches to avoid holding the
-- write lock on large tables (mirrors the other retention deletes).
DELETE FROM host_services
WHERE id IN (
    SELECT sub.id FROM host_services AS sub WHERE sub.updated_at < ? LIMIT ?
);
