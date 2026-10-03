package store

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/testutil"
)

// TestRecordServices_PortZeroIdentityRescanIdempotent pins the field-found
// 2026-10-03 bug: port-0 service identities (the hostname-derived miot rows)
// were excluded from the scoped DELETE's port IN-list, so a rescan re-inserted
// the same (ip, service, 0) row and tripped UNIQUE(ip, service, port) — one
// WARN per host per scan once a network gets rescanned regularly. The rescan
// must be silent and leave exactly one row.
func TestRecordServices_PortZeroIdentityRescanIdempotent(t *testing.T) {
	dbConn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { dbConn.Close() })
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	repo := NewSQLiteRepository(dbConn, Options{}, logger)
	ctx := context.Background()

	miot := []scannerv2.ServiceIdentity{
		{Service: "miot", Port: 0, Protocol: "hostname", Confidence: 0.55},
	}
	require.NoError(t, repo.RecordServices(ctx, "10.0.0.9", miot, nil))
	require.NoError(t, repo.RecordServices(ctx, "10.0.0.9", miot, nil), "rescan with the same port-0 identity")

	require.NotContains(t, buf.String(), "insert host_service row failed",
		"a rescan re-reporting a port-0 identity must not hit the unique index")

	var n int
	require.NoError(t, dbConn.QueryRow(
		`SELECT COUNT(*) FROM host_services WHERE ip = '10.0.0.9' AND service = 'miot'`).Scan(&n))
	require.Equal(t, 1, n, "exactly one port-0 row after two scans")
}
