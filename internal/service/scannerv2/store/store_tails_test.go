// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/testutil"
)

// TestRepository_DeadDB_FirstErrorTails pins each write method's first-error
// branch on a dead handle (begin-tx / lookup failures return, never panic).
func TestRepository_DeadDB_FirstErrorTails(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	repo := NewSQLiteRepository(conn, Options{PersistRawEvidence: true}, nil)

	require.Error(t, repo.RecordEvidence(context.Background(), []scannerv2.Evidence{{IP: "10.0.0.1"}}))
	require.Error(t, repo.RecordServices(context.Background(), "10.0.0.1",
		[]scannerv2.ServiceIdentity{{Service: "http", Port: 80}}, nil))
	// RecordTLSCerts begins a tx directly: a dead handle shows up as an error.
	require.Error(t, repo.RecordTLSCerts(context.Background(), "10.0.0.1",
		[]scannerv2.TLSCertRecord{{IP: "10.0.0.1", Port: 443}}))
	// RecordNeighbors never fails the caller: an unresolvable device is logged and
	// swallowed (nil), never returned.
	require.NoError(t, repo.RecordNeighbors(context.Background(), "10.0.0.1",
		[]scannerv2.NeighborSpec{{NeighborMAC: "aa:bb:cc:dd:ee:ff", Protocol: "LLDP"}}))
	_, err = repo.ResolveDeviceIdentity(context.Background(), "aa:bb:cc:dd:ee:ff", "10.0.0.1", sql.NullInt64{})
	require.Error(t, err)
}

// TestRecordEvidence_ZeroObservedAtStampsNow pins the zero-timestamp
// normalization: an evidence without ObservedAt is stamped at insert time
// instead of writing the zero value into the epoch-millisecond column.
func TestRecordEvidence_ZeroObservedAtStampsNow(t *testing.T) {
	repo, ctx := newRepo(t, Options{PersistRawEvidence: true})
	before := time.Now().Add(-time.Second)
	err := repo.RecordEvidence(ctx, []scannerv2.Evidence{{
		IP: "10.0.0.9", Source: "active:tcp", Kind: "port_open", Port: 443,
		RawData: map[string]string{"port": "443"},
	}})
	require.NoError(t, err)

	var n int
	require.NoError(t, repo.db.QueryRow(
		`SELECT COUNT(*) FROM service_evidence WHERE ip = '10.0.0.9' AND observed_at > ?`,
		before.UnixMilli()).Scan(&n))
	require.Equal(t, 1, n, "zero ObservedAt must be stamped with insert time")
}
