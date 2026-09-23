// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package routes

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/testutil"
)

// TestResolveNetworkID pins the startup identity upsert: the instance's
// network name resolves to a row (created on first boot), and an existing row
// gets its cidr/site REFRESHED when the config changes (a stale row must not
// pin the old subnet).
func TestResolveNetworkID(t *testing.T) {
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cfg := &config.Config{Network: config.NetworkConfig{Name: "", CIDR: "192.168.70.0/24", Site: "hq"}}

	// Empty name falls back to "default".
	id1 := resolveNetworkID(db, cfg)
	require.NotZero(t, id1)

	var name string
	var cidr, site *string
	require.NoError(t, db.QueryRow(`SELECT name, cidr, site FROM networks WHERE id=?`, id1).Scan(&name, &cidr, &site))
	require.Equal(t, "default", name)
	require.NotNil(t, cidr)
	require.Equal(t, "192.168.70.0/24", *cidr)

	// Second boot with a CHANGED cidr/site: same row, refreshed attributes.
	cfg.Network.CIDR = "192.168.71.0/24"
	cfg.Network.Site = "branch"
	id2 := resolveNetworkID(db, cfg)
	require.Equal(t, id1, id2, "same name must resolve to the same row")
	require.NoError(t, db.QueryRow(`SELECT cidr, site FROM networks WHERE id=?`, id1).Scan(&cidr, &site))
	require.Equal(t, "192.168.71.0/24", *cidr)
	require.Equal(t, "branch", *site)

	// A different name resolves to a different row.
	cfg.Network.Name = "lan-alt"
	id3 := resolveNetworkID(db, cfg)
	require.NotEqual(t, id1, id3)
}
