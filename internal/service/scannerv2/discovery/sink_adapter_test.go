// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You can use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/runner"
	"mibee-steward/internal/service/scannerv2/store"
)

// The agent-side Forward hook fires after the local bridge Apply, carrying the
// same report; the center leaves Forward nil and nothing changes for it.
func TestSinkAdapter_ForwardHook(t *testing.T) {
	dbConn := memoryDB(t)
	queries := sqldb.New(dbConn)
	rn := runner.New(nil, queries, dbConn, nil, 0, nil)
	rn.SetRepo(store.NewSQLiteRepository(dbConn, store.Options{}, nil))

	var forwarded []scannerv2.HostReport
	adapter := SinkAdapter{
		Runner:  rn,
		Forward: func(_ context.Context, rep scannerv2.HostReport) { forwarded = append(forwarded, rep) },
	}
	rep := scannerv2.HostReport{IP: "192.168.62.99", Alive: true,
		Device: scannerv2.DeviceRef{IP: "192.168.62.99", Fields: map[string]string{"mac": "aa:bb:cc:dd:ee:99"}}}

	isNew := adapter.Apply(context.Background(), rep)
	require.True(t, isNew)
	require.Len(t, forwarded, 1, "agent-side adapter forwards the applied report")
	require.Equal(t, "192.168.62.99", forwarded[0].IP)

	// Center-style adapter (no Forward) still applies cleanly.
	plain := SinkAdapter{Runner: rn}
	require.False(t, plain.Apply(context.Background(), rep), "second sighting is not new")
}
