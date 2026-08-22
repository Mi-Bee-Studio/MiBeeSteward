-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
--
-- This file is part of MiBee Steward, distributed under the GNU Affero General
-- Public License v3.0 or later. See LICENSE for the full text. A commercial
-- license is available for use cases the AGPL does not accommodate; see
-- LICENSE-COMMERCIAL.md.

-- name: UpsertAgentStatus :exec
-- Refresh the fleet snapshot on every authenticated agent report (#278).
-- clock_offset is passed precomputed by the handler (receive_time - scanned_at).
INSERT INTO agent_status (agent_id, version, go_version, hostname, uptime_seconds,
    clock_offset_seconds, scans_total, last_report_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(agent_id) DO UPDATE SET
    version = excluded.version,
    go_version = excluded.go_version,
    hostname = excluded.hostname,
    uptime_seconds = excluded.uptime_seconds,
    clock_offset_seconds = excluded.clock_offset_seconds,
    scans_total = excluded.scans_total,
    last_report_at = excluded.last_report_at;

-- name: ListAgentStatus :many
-- All fleet snapshots oldest-report-first (the stalest agent draws the eye).
SELECT agent_id, version, go_version, hostname, uptime_seconds,
    clock_offset_seconds, scans_total, last_report_at
FROM agent_status
ORDER BY last_report_at ASC;
