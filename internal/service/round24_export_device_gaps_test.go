// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package service

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sqldb "mibee-steward/internal/db"
	"mibee-steward/internal/domain"
	"mibee-steward/internal/testutil"
)

// flakyWriter succeeds for the first `ok` writes, then fails — lets a test
// pinpoint exactly WHICH write in a streaming pipeline trips the error branch.
type flakyWriter struct {
	ok    int
	n     int
	fail  error
	wrote strings.Builder
}

func (w *flakyWriter) Write(p []byte) (int, error) {
	if w.n >= w.ok {
		return 0, w.fail
	}
	w.n++
	return w.wrote.Write(p)
}

var errFlaky = errors.New("flaky writer")

// TestStreamCSV_ErrorTails pins the CSV pipeline's failure modes: BOM write,
// header write, context cancellation, fetch error, and record write.
func TestStreamCSV_ErrorTails(t *testing.T) {
	svc := &ExportService{}
	headers := []string{"a", "b"}

	// BOM write fails immediately.
	err := svc.streamCSV(context.Background(), &flakyWriter{ok: 0, fail: errFlaky}, headers,
		func(int64) ([][]string, error) { return nil, nil })
	require.ErrorContains(t, err, "BOM")

	// Header write fails (BOM ok).
	err = svc.streamCSV(context.Background(), &flakyWriter{ok: 1, fail: errFlaky}, headers,
		func(int64) ([][]string, error) { return nil, nil })
	require.ErrorIs(t, err, errFlaky)

	// Context already canceled before the first fetch.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	err = svc.streamCSV(canceled, &flakyWriter{ok: 100, fail: errFlaky}, headers,
		func(int64) ([][]string, error) { return nil, nil })
	require.ErrorIs(t, err, context.Canceled)

	// Fetch fails.
	err = svc.streamCSV(context.Background(), &flakyWriter{ok: 100, fail: errFlaky}, headers,
		func(int64) ([][]string, error) { return nil, errFlaky })
	require.ErrorContains(t, err, "failed to fetch records")

	// Record write fails (BOM+header ok, first record write fails).
	err = svc.streamCSV(context.Background(), &flakyWriter{ok: 2, fail: errFlaky}, headers,
		func(int64) ([][]string, error) { return [][]string{{"1", "2"}}, nil })
	require.ErrorIs(t, err, errFlaky)
}

// TestStreamJSON_ErrorTails pins the JSON pipeline's failure modes: opening
// bracket, context cancellation (with the closing bracket), fetch error,
// comma write, and an un-encodable record.
func TestStreamJSON_ErrorTails(t *testing.T) {
	svc := &ExportService{}

	// Opening bracket fails.
	err := svc.streamJSON(context.Background(), &flakyWriter{ok: 0, fail: errFlaky},
		func(int64) ([]map[string]interface{}, error) { return nil, nil })
	require.ErrorContains(t, err, "opening bracket")

	// Context already canceled — the writer still gets its "]".
	w := &flakyWriter{ok: 10, fail: errFlaky}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	err = svc.streamJSON(canceled, w, func(int64) ([]map[string]interface{}, error) { return nil, nil })
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, "[]", w.wrote.String(), "array is closed before returning")

	// Fetch fails.
	err = svc.streamJSON(context.Background(), &flakyWriter{ok: 10, fail: errFlaky},
		func(int64) ([]map[string]interface{}, error) { return nil, errFlaky })
	require.ErrorContains(t, err, "failed to fetch records")

	// Comma write fails after the first record (bracket + record ok).
	err = svc.streamJSON(context.Background(), &flakyWriter{ok: 2, fail: errFlaky},
		func(int64) ([]map[string]interface{}, error) {
			return []map[string]interface{}{{"a": 1}, {"b": 2}}, nil
		})
	require.ErrorIs(t, err, errFlaky)

	// NaN cannot be encoded as JSON — the encode branch fails while writes
	// still succeed.
	err = svc.streamJSON(context.Background(), &flakyWriter{ok: 100, fail: errFlaky},
		func(int64) ([]map[string]interface{}, error) {
			return []map[string]interface{}{{"a": math.NaN()}}, nil
		})
	require.ErrorContains(t, err, "encode")
}

// TestExportService_UnsupportedFormatWriters sanity-walks the entry points
// with a format the switch defaults on CSV for — the JSON branch is taken
// explicitly elsewhere; this pins the default fall-through plus a dead-DB
// first-fetch error per surface.
func TestExportService_DeadDB_FirstFetchFails(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	dead := sqldb.New(conn)
	svc := NewExportService(dead, dead, conn)

	var sb strings.Builder
	require.Error(t, svc.Devices(context.Background(), "csv", &sb, domain.Scope{Global: true}))
	require.Error(t, svc.Devices(context.Background(), "json", &sb, domain.Scope{Global: true}))
	require.Error(t, svc.HeartbeatResults(context.Background(), 1, "csv", &sb))
	require.Error(t, svc.HeartbeatResults(context.Background(), 1, "json", &sb))
	require.Error(t, svc.AuditLogs(context.Background(), "csv", &sb))
	require.Error(t, svc.AuditLogs(context.Background(), "json", &sb))
}

// TestDeviceRepository_ListFiltered_FilterArgs drives the dynamic-filter
// argument branches (created-window, network, search) and the DESC direction
// through the raw-SQL list path.
func TestDeviceRepository_ListFiltered_FilterArgs(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	repo := NewDeviceRepository(conn)
	ctx := context.Background()

	seed := func(name, ip string, networkID any) {
		_, err := conn.Exec(`INSERT INTO devices (name, ip_address, mac_address, status, network_id, device_uuid, created_at, updated_at)
			VALUES (?, ?, '', 'online', ?, ?, '2026-01-02 03:04:05', '2026-01-02 03:04:05')`,
			name, ip, networkID, "seed-"+ip)
		require.NoError(t, err)
	}
	seed("cam-a", "10.1.0.10", nil)
	seed("cam-b", "10.1.0.11", 3)

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	netID := int64(3)

	got, err := repo.ListFiltered(ctx, domain.DeviceFilter{
		Limit:         50,
		CreatedAtFrom: &from,
		CreatedAtTo:   &to,
		NetworkID:     &netID,
		Search:        "cam-b",
		SortBy:        "name",
		Order:         "desc",
		Status:        "online",
	})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "cam-b", got[0].Device.Name)

	// Window that excludes everything (created before the from-bound).
	early := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err = repo.ListFiltered(ctx, domain.DeviceFilter{Limit: 50, CreatedAtFrom: &from, CreatedAtTo: &early})
	require.NoError(t, err)
	require.Empty(t, got)

	// ListFilteredWithCount agrees with the filtered list.
	list, total, err := repo.ListFilteredWithCount(ctx, domain.DeviceFilter{Limit: 50, NetworkID: &netID})
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.EqualValues(t, 1, total)
}

// TestDeviceRepository_ListFilteredWithCount_DeadDB pins the tx-open failure
// wrap of the consistent list+count path.
func TestDeviceRepository_ListFilteredWithCount_DeadDB(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	repo := NewDeviceRepository(conn)
	_, _, err = repo.ListFilteredWithCount(context.Background(), domain.DeviceFilter{})
	require.ErrorContains(t, err, "begin read tx")
}
