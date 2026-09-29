// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. You can use, copy, modify, and
// redistribute it under those terms; see LICENSE for the full text. A
// commercial license is available for use cases the AGPLv3 does not
// accommodate; see LICENSE-COMMERCIAL.md.

package main

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

// Field-found shape: the agent's shadow devices table kept silently-dead rows
// the center had already correctly dropped (MAC-less identities last seen
// days earlier), and scan_results grew unbounded (95 MB in a week).
func TestSweepStaleAgentData(t *testing.T) {
	db, err := sql.Open("sqlite", "file:mibeeagent_sweep_test?mode=memory&cache=shared")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	// Single connection: the shared in-memory DB must not be torn down when a
	// pooled conn recycles mid-test.
	db.SetMaxOpenConns(1)
	_, err = db.Exec(agentSchema)
	require.NoError(t, err)

	seed := `
INSERT INTO devices (name, ip_address, mac_address, scan_attributes, last_seen, created_at, updated_at) VALUES
  ('gone-no-mac', '192.0.2.101', '',     '{}', datetime('now','-3 days'),  datetime('now','-3 days'), datetime('now','-3 days')),
  ('fresh-no-mac','192.0.2.102', '',     '{}', datetime('now','-1 hour'), datetime('now','-1 hour'), datetime('now','-1 hour')),
  ('gone-mac',    '192.0.2.103', '02:00:00:00:00:03', '{}', datetime('now','-8 days'), datetime('now','-8 days'), datetime('now','-8 days')),
  ('quiet-mac',   '192.0.2.104', '02:00:00:00:00:04', '{}', datetime('now','-3 days'), datetime('now','-3 days'), datetime('now','-3 days')),
  ('mac-in-attrs','192.0.2.105', '',     '{"mac":"02:00:00:00:00:05"}', datetime('now','-3 days'), datetime('now','-3 days'), datetime('now','-3 days'));
INSERT INTO scan_tasks (id, name, targets) VALUES (0, 't', '192.0.2.0/24');
INSERT INTO scan_results (task_id, ip, alive, scanned_at)
  VALUES (0,'192.0.2.1',1,datetime('now','-20 days')), (0,'192.0.2.2',1,datetime('now','-2 days')),
         (0,'192.0.2.3',1,datetime('now','-4 days')), (0,'192.0.2.4',1,datetime('now','-71 hours'));
`
	_, err = db.Exec(seed)
	require.NoError(t, err)

	sweepStaleAgentData(context.Background(), db, slog.Default())

	var devices []string
	rows, err := db.Query(`SELECT name FROM devices ORDER BY name`)
	require.NoError(t, err)
	for rows.Next() {
		var n string
		require.NoError(t, rows.Scan(&n))
		devices = append(devices, n)
	}
	rows.Close()
	// gone-no-mac: silent MAC-less >24h → pruned.
	// fresh-no-mac: recent → kept.
	// gone-mac: silent >7d → pruned. quiet-mac: 3d < 7d → kept.
	// mac-in-attrs: MAC-less column but scan_attributes carries a MAC → kept.
	require.Equal(t, []string{"fresh-no-mac", "mac-in-attrs", "quiet-mac"}, devices)

	var results int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM scan_results`).Scan(&results))
	require.Equal(t, 2, results, "72h retention: the 2-day-old and 71-hour-old rows survive; the 4-day-old and 20-day-old are pruned")
}
