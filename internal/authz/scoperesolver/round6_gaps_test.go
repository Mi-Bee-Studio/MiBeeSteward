// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package scoperesolver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

func TestResolver_ModeAndInvalidateAll(t *testing.T) {
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	r := New(db, domain.ScopeModeClosed)
	require.Equal(t, domain.ScopeModeClosed, r.Mode())

	// nil-safety: a nil resolver answers open + no-op invalidate (callers may
	// hold a nil resolver in open mode).
	var nilR *Resolver
	require.Equal(t, domain.ScopeModeOpen, nilR.Mode())
	require.NotPanics(t, nilR.InvalidateAll)

	// InvalidateAll is callable and idempotent on a live resolver.
	r.InvalidateAll()
	r.InvalidateAll()
}

func TestDeleteByUserNetwork(t *testing.T) {
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()

	_, err = db.ExecContext(ctx,
		`INSERT INTO user_network_grants (user_id, network_id) VALUES (7, 3)`)
	require.NoError(t, err)

	deleted, err := DeleteByUserNetwork(ctx, db, 7, 3)
	require.NoError(t, err)
	require.True(t, deleted)

	// Second delete of the same pair: nothing left → false.
	deleted, err = DeleteByUserNetwork(ctx, db, 7, 3)
	require.NoError(t, err)
	require.False(t, deleted)

	// Surrogate-id delete for contrast (same table, different keying).
	res, err = db.ExecContext(ctx,
		`INSERT INTO user_network_grants (user_id, network_id) VALUES (8, 3)`)
	require.NoError(t, err)
	grantID, _ = res.LastInsertId()
	deleted, err = Delete(ctx, db, grantID)
	require.NoError(t, err)
	require.True(t, deleted)
}
