package archive

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

func TestListArchivedAndDossier(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	now := time.Now()

	// One archived + one active device.
	archivedID := insertDevice(t, conn, "filed", "scanner_v2", "offline", "aa:bb:cc:dd:ee:41", "192.0.2.41",
		ptr(now.AddDate(0, 0, -30)), ptr(now.AddDate(0, 0, -20)), nil)
	insertDevice(t, conn, "live", "scanner_v2", "online", "aa:bb:cc:dd:ee:42", "192.0.2.42",
		nil, nil, nil)
	// Dossier material: an archive event + a change_log row.
	addEvent(t, conn, archivedID, EventArchived, TriggerAutoOffline, now.AddDate(0, 0, -20))
	_, err = conn.ExecContext(ctx,
		`INSERT INTO change_log (change_type, entity_type, entity_id, detected_at) VALUES ('device_added', 'device', ?, ?)`,
		archivedID, now.AddDate(0, 0, -30))
	require.NoError(t, err)

	svc := New(db.New(conn), config.ArchiveConfig{
		OfflineDays: 7, RestoreOnlineMinutes: 60, SweepIntervalSeconds: 60,
	}, nil)

	items, total, err := svc.ListArchived(ctx, 20, 0)
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, items, 1)
	require.Equal(t, archivedID, items[0].ID)
	require.Equal(t, "filed", items[0].Name)
	require.False(t, items[0].ArchivedAt.IsZero())
	require.True(t, items[0].Periodic == false)

	entries, err := svc.Dossier(ctx, archivedID, 100)
	require.NoError(t, err)
	kinds := map[string]bool{}
	for _, e := range entries {
		kinds[e.Kind] = true
	}
	require.True(t, kinds["archive_event"], "dossier must include the archive event")
	require.True(t, kinds["change"], "dossier must include the change_log row")
	// Newest-first ordering.
	for i := 1; i < len(entries); i++ {
		require.False(t, entries[i].OccurredAt.After(entries[i-1].OccurredAt), "dossier must be newest-first")
	}
}

func TestSetThresholdOverride(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	now := time.Now()

	id := insertDevice(t, conn, "special", "scanner_v2", "offline", "aa:bb:cc:dd:ee:43", "192.0.2.43",
		ptr(now.AddDate(0, 0, -3)), nil, nil)
	svc := New(db.New(conn), config.ArchiveConfig{OfflineDays: 7, RestoreOnlineMinutes: 60}, nil)

	require.NoError(t, svc.SetThresholdOverride(ctx, id, 2))
	var ov int64
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT COALESCE(archive_offline_days_override, 0) FROM devices WHERE id = ?`, id).Scan(&ov))
	require.Equal(t, int64(2), ov)

	// 0 clears back to global.
	require.NoError(t, svc.SetThresholdOverride(ctx, id, 0))
	require.NoError(t, conn.QueryRowContext(ctx,
		`SELECT COALESCE(archive_offline_days_override, 0) FROM devices WHERE id = ?`, id).Scan(&ov))
	require.Equal(t, int64(0), ov)
}
