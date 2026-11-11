package archive

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// insertDevice inserts a devices row with full control over the archive-state
// machine fields. Mirrors the cleanup test helper: CreateDevice defaults
// scan_source='manual' and cannot set offline_since/archived_at/online_since,
// all critical here.
func insertDevice(t *testing.T, conn *sql.DB, name, scanSource, status, mac, ip string, offlineSince, archivedAt, onlineSince *time.Time) int64 {
	t.Helper()
	fmt := func(p *time.Time) any {
		if p == nil {
			return nil
		}
		return p.UTC().Format(time.RFC3339Nano)
	}
	res, err := conn.ExecContext(context.Background(), `
		INSERT INTO devices (device_uuid, name, type, status, scan_source, mac_address, ip_address,
		                     offline_since, archived_at, online_since, tags, scan_attributes, user_attributes)
		VALUES (?, ?, 'other', ?, ?, ?, ?, ?, ?, ?, '{}', '{}', '{}')`,
		name+"-uuid", name, status, scanSource, mac, ip, fmt(offlineSince), fmt(archivedAt), fmt(onlineSince))
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

func ptr(t time.Time) *time.Time { return &t }

func newSvc(t *testing.T, conn *sql.DB) *Service {
	t.Helper()
	return New(db.New(conn), config.ArchiveConfig{
		OfflineDays:          7,
		RestoreOnlineMinutes: 60,
		SweepIntervalSeconds: 60,
	}, nil)
}

func deviceState(t *testing.T, conn *sql.DB, id int64) (archived bool, pin string, onlineSince sql.NullString) {
	t.Helper()
	require.NoError(t, conn.QueryRowContext(context.Background(),
		`SELECT archived_at IS NOT NULL, archive_pin, CAST(online_since AS TEXT) FROM devices WHERE id = ?`, id,
	).Scan(&archived, &pin, &onlineSince))
	return
}

func countEvents(t *testing.T, conn *sql.DB, deviceID int64, event, triggeredBy string) int64 {
	t.Helper()
	var n int64
	require.NoError(t, conn.QueryRowContext(context.Background(),
		`SELECT count(*) FROM asset_archive_events WHERE device_id = ? AND event = ? AND triggered_by = ?`,
		deviceID, event, triggeredBy).Scan(&n))
	return n
}

func TestAutoArchive_AfterThreshold(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	id := insertDevice(t, conn, "gone", "scanner_v2", "offline", "aa:bb:cc:dd:ee:01", "192.0.2.1",
		ptr(time.Now().AddDate(0, 0, -8)), nil, nil)

	newSvc(t, conn).runOnce(ctx)

	archived, pin, _ := deviceState(t, conn, id)
	require.True(t, archived, "offline 8d (threshold 7d) must be archived")
	require.Equal(t, PinNone, pin)
	require.Equal(t, int64(1), countEvents(t, conn, id, EventArchived, TriggerAutoOffline),
		"auto-archive must write exactly one archived/auto_offline event")
}

func TestAutoArchive_BelowThresholdStays(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	id := insertDevice(t, conn, "short-gone", "scanner_v2", "offline", "aa:bb:cc:dd:ee:02", "192.0.2.2",
		ptr(time.Now().AddDate(0, 0, -3)), nil, nil)

	newSvc(t, conn).runOnce(ctx)

	archived, _, _ := deviceState(t, conn, id)
	require.False(t, archived, "offline 3d (threshold 7d) must stay in the asset library")
	require.Equal(t, int64(0), countEvents(t, conn, id, EventArchived, TriggerAutoOffline))
}

func TestAutoArchive_ManualSourceSkipped(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	// Manual asset: only responds to manual archive.
	id := insertDevice(t, conn, "handmade", "manual", "offline", "aa:bb:cc:dd:ee:03", "192.0.2.3",
		ptr(time.Now().AddDate(0, 0, -30)), nil, nil)

	newSvc(t, conn).runOnce(ctx)

	archived, _, _ := deviceState(t, conn, id)
	require.False(t, archived, "manual device must never be auto-archived")
}

func TestAutoArchive_ForceActivePinSkipped(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	id := insertDevice(t, conn, "pinned-live", "scanner_v2", "offline", "aa:bb:cc:dd:ee:04", "192.0.2.4",
		ptr(time.Now().AddDate(0, 0, -30)), nil, nil)
	_, err = conn.ExecContext(ctx, `UPDATE devices SET archive_pin = 'force_active' WHERE id = ?`, id)
	require.NoError(t, err)

	newSvc(t, conn).runOnce(ctx)

	archived, pin, _ := deviceState(t, conn, id)
	require.False(t, archived, "force_active pin must block auto-archive")
	require.Equal(t, PinForceActive, pin)
}

func TestAutoArchive_PerDeviceOverrideWins(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	// Override 3d: offline 5d crosses the override but not the global 7d.
	id := insertDevice(t, conn, "special", "scanner_v2", "offline", "aa:bb:cc:dd:ee:05", "192.0.2.5",
		ptr(time.Now().AddDate(0, 0, -5)), nil, nil)
	_, err = conn.ExecContext(ctx, `UPDATE devices SET archive_offline_days_override = 3 WHERE id = ?`, id)
	require.NoError(t, err)
	// Control: global threshold only.
	ctl := insertDevice(t, conn, "control", "scanner_v2", "offline", "aa:bb:cc:dd:ee:06", "192.0.2.6",
		ptr(time.Now().AddDate(0, 0, -5)), nil, nil)

	newSvc(t, conn).runOnce(ctx)

	archived, _, _ := deviceState(t, conn, id)
	require.True(t, archived, "per-device override (3d) must win over the global 7d")
	ctlArchived, _, _ := deviceState(t, conn, ctl)
	require.False(t, ctlArchived, "control on the global threshold (7d) stays")
}

// TestRestore_ContinuousOnline runs the full tick sequence on an archived
// device that has been continuously online past the threshold: it must return
// to the asset library with a restored/auto_restore event.
func TestRestore_ContinuousOnline(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	id := insertDevice(t, conn, "back", "scanner_v2", "online", "aa:bb:cc:dd:ee:07", "192.0.2.7",
		nil, ptr(time.Now().AddDate(0, 0, -2)), ptr(time.Now().Add(-61*time.Minute)))

	newSvc(t, conn).runOnce(ctx)

	archived, _, onlineSince := deviceState(t, conn, id)
	require.False(t, archived, "61min continuous online must auto-restore")
	require.False(t, onlineSince.Valid, "online_since must clear on restore")
	require.Equal(t, int64(1), countEvents(t, conn, id, EventRestored, TriggerAutoRestore))
}

// TestRestore_NotYetContinuous stays archived while the online stretch is
// still below the threshold.
func TestRestore_NotYetContinuous(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	id := insertDevice(t, conn, "warming", "scanner_v2", "online", "aa:bb:cc:dd:ee:08", "192.0.2.8",
		nil, ptr(time.Now().AddDate(0, 0, -2)), ptr(time.Now().Add(-10*time.Minute)))

	newSvc(t, conn).runOnce(ctx)

	archived, _, _ := deviceState(t, conn, id)
	require.True(t, archived, "10min online (< 60min) must stay archived")
	require.Equal(t, int64(0), countEvents(t, conn, id, EventRestored, TriggerAutoRestore))
}

// TestBlip_InterruptedOnlineRecordsBlipAndStaysArchived: the 1-2 brief online
// appearances case — the online episode ends before the threshold, so the
// device stays archived and the episode is recorded as online_blip (the #664
// pattern learner's input).
func TestBlip_InterruptedOnlineRecordsBlipAndStaysArchived(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	// Online 12min ago, but already offline again by now.
	id := insertDevice(t, conn, "blipper", "scanner_v2", "offline", "aa:bb:cc:dd:ee:09", "192.0.2.9",
		nil, ptr(time.Now().AddDate(0, 0, -2)), ptr(time.Now().Add(-12*time.Minute)))

	newSvc(t, conn).runOnce(ctx)

	archived, _, onlineSince := deviceState(t, conn, id)
	require.True(t, archived, "a 12min blip must not restore the device")
	require.False(t, onlineSince.Valid, "the interrupted online clock must clear")
	require.Equal(t, int64(1), countEvents(t, conn, id, EventOnlineBlip, TriggerAutoRestore))
}

func TestRestore_ForceArchivePinNeverAutoRestores(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	// Online for days, but force-archived: stays in the archive.
	id := insertDevice(t, conn, "locked", "scanner_v2", "online", "aa:bb:cc:dd:ee:10", "192.0.2.10",
		nil, ptr(time.Now().AddDate(0, 0, -2)), ptr(time.Now().Add(-48*time.Hour)))
	_, err = conn.ExecContext(ctx, `UPDATE devices SET archive_pin = 'force_archive' WHERE id = ?`, id)
	require.NoError(t, err)

	newSvc(t, conn).runOnce(ctx)

	archived, pin, _ := deviceState(t, conn, id)
	require.True(t, archived, "force_archive pin must block auto-restore even after long online")
	require.Equal(t, PinForceArchive, pin)
	require.Equal(t, int64(0), countEvents(t, conn, id, EventRestored, TriggerAutoRestore))
}

// TestStampOnline_OnlineObservationStartsClock: an archived device observed
// online WITHOUT an online_since yet gets stamped (restore timer starts).
func TestStampOnline_OnlineObservationStartsClock(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	id := insertDevice(t, conn, "just-seen", "scanner_v2", "online", "aa:bb:cc:dd:ee:11", "192.0.2.11",
		nil, ptr(time.Now().AddDate(0, 0, -2)), nil)

	newSvc(t, conn).runOnce(ctx)

	archived, _, onlineSince := deviceState(t, conn, id)
	require.True(t, archived, "fresh online observation must not restore immediately")
	require.True(t, onlineSince.Valid, "online_since must be stamped on first online observation")
}

// fakeSettings implements SettingsGetter from a raw JSON blob.
type fakeSettings struct{ raw string }

func (f fakeSettings) Get(key string, dst any) bool {
	if key != SettingKeyEngine {
		return false
	}
	return json.Unmarshal([]byte(f.raw), dst) == nil
}

// TestSettingsOverlay_WinsOverConfig: the settings-center overlay threshold
// (2d) must beat the YAML config (7d) on every tick.
func TestSettingsOverlay_WinsOverConfig(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	id := insertDevice(t, conn, "overlay", "scanner_v2", "offline", "aa:bb:cc:dd:ee:12", "192.0.2.12",
		ptr(time.Now().AddDate(0, 0, -3)), nil, nil)

	svc := newSvc(t, conn).SetSettingsSource(fakeSettings{raw: `{"offline_days":2,"restore_online_minutes":30}`})
	svc.runOnce(ctx)

	archived, _, _ := deviceState(t, conn, id)
	require.True(t, archived, "overlay offline_days=2 must archive a 3d-offline device")
}

func TestManualArchiveAndRestore(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	// A manual asset: manual archive applies even though auto-archive never would.
	id := insertDevice(t, conn, "handmade", "manual", "online", "aa:bb:cc:dd:ee:13", "192.0.2.13",
		nil, nil, nil)
	svc := newSvc(t, conn)

	require.NoError(t, svc.ArchiveDeviceManually(ctx, id, "retired to shelf"))
	archived, _, _ := deviceState(t, conn, id)
	require.True(t, archived)
	require.Equal(t, int64(1), countEvents(t, conn, id, EventArchived, TriggerManual))

	// Idempotence surfaced as an error.
	require.ErrorIs(t, svc.ArchiveDeviceManually(ctx, id, "again"), ErrAlreadyArchived)

	// Manual restore works without a pin.
	require.NoError(t, svc.RestoreDeviceManually(ctx, id, false))
	archived, _, _ = deviceState(t, conn, id)
	require.False(t, archived)
	require.Equal(t, int64(1), countEvents(t, conn, id, EventRestored, TriggerManual))

	// Restore of a non-archived device is an error.
	require.ErrorIs(t, svc.RestoreDeviceManually(ctx, id, false), ErrNotArchived)
}

func TestManualRestore_BlockedByPinUnlessForce(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	id := insertDevice(t, conn, "locked", "scanner_v2", "offline", "aa:bb:cc:dd:ee:14", "192.0.2.14",
		nil, ptr(time.Now().AddDate(0, 0, -1)), nil)
	svc := newSvc(t, conn)

	require.NoError(t, svc.SetPin(ctx, id, PinForceArchive))
	require.Equal(t, int64(1), countEvents(t, conn, id, EventPinSet, TriggerManual))

	// Without force: blocked.
	require.ErrorIs(t, svc.RestoreDeviceManually(ctx, id, false), ErrPinned)

	// With force: pin cleared (pin_cleared event) + restored.
	require.NoError(t, svc.RestoreDeviceManually(ctx, id, true))
	archived, pin, _ := deviceState(t, conn, id)
	require.False(t, archived)
	require.Equal(t, PinNone, pin)
	require.Equal(t, int64(1), countEvents(t, conn, id, EventPinCleared, TriggerManual))
	require.Equal(t, int64(1), countEvents(t, conn, id, EventRestored, TriggerManual))
}

func TestSetPin_Validation(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	id := insertDevice(t, conn, "validator", "scanner_v2", "online", "aa:bb:cc:dd:ee:15", "192.0.2.15",
		nil, nil, nil)
	svc := newSvc(t, conn)

	require.ErrorIs(t, svc.SetPin(ctx, id, "bogus"), ErrInvalidPin)
	require.NoError(t, svc.SetPin(ctx, id, PinForceActive))
	_, pin, _ := deviceState(t, conn, id)
	require.Equal(t, PinForceActive, pin)
	require.NoError(t, svc.SetPin(ctx, id, PinNone))
	_, pin, _ = deviceState(t, conn, id)
	require.Equal(t, PinNone, pin)
	require.Equal(t, int64(1), countEvents(t, conn, id, EventPinCleared, TriggerManual))

	p, err := NormalizePin(" force_archive ")
	require.NoError(t, err)
	require.Equal(t, PinForceArchive, p)
	_, err = NormalizePin("nope")
	require.ErrorIs(t, err, ErrInvalidPin)
}

// TestAutoArchive_NoMacDeviceSameRule: the unified-window decision (#663) —
// no-MAC devices follow the same 7d threshold (the old 24h fast-prune is
// gone).
func TestAutoArchive_NoMacDeviceSameRule(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	early := insertDevice(t, conn, "nomac-early", "scanner_v2", "offline", "", "192.0.2.16",
		ptr(time.Now().AddDate(0, 0, -2)), nil, nil)
	late := insertDevice(t, conn, "nomac-late", "scanner_v2", "offline", "", "192.0.2.17",
		ptr(time.Now().AddDate(0, 0, -9)), nil, nil)

	newSvc(t, conn).runOnce(ctx)

	earlyArchived, _, _ := deviceState(t, conn, early)
	require.False(t, earlyArchived, "no-MAC device at 2d (unified 7d window) must stay")
	lateArchived, _, _ := deviceState(t, conn, late)
	require.True(t, lateArchived, "no-MAC device past 7d must be archived (same rule as with-MAC)")
}

// TestRestoreManually_IPConflict (#737): an archived record's ip_address is
// its LAST RECORDED address. When an ACTIVE device meanwhile holds that
// address, a manual restore must be rejected (ErrIPConflict) — two live rows
// cannot share the slot, and the user resolves the duplicate consciously.
// Once the address is free again, the same restore succeeds.
func TestRestoreManually_IPConflict(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	ghost := insertDevice(t, conn, "ghost", "scanner_v2", "offline", "aa:bb:cc:dd:ee:10", "192.0.2.10",
		nil, ptr(time.Now().AddDate(0, 0, -2)), nil)
	occupant := insertDevice(t, conn, "newcomer", "scanner_v2", "online", "bb:bb:bb:bb:bb:05", "192.0.2.10",
		nil, nil, nil)

	svc := newSvc(t, conn)
	err = svc.RestoreDeviceManually(context.Background(), ghost, false)
	require.ErrorIs(t, err, ErrIPConflict, "the recorded address is now held by an active device")

	// The address frees up → the same restore succeeds.
	_, err = conn.ExecContext(context.Background(), `DELETE FROM devices WHERE id = ?`, occupant)
	require.NoError(t, err)
	require.NoError(t, svc.RestoreDeviceManually(context.Background(), ghost, false))
	archived, _, _ := deviceState(t, conn, ghost)
	require.False(t, archived)
}

// TestRestore_AutoSkipWhenIPClaimed (#737): the auto-restore path skips when
// the recorded address is claimed by an active device — the row stays
// archived (its online clock keeps running) instead of pushing a second live
// row into the slot.
func TestRestore_AutoSkipWhenIPClaimed(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()

	ghost := insertDevice(t, conn, "ghost", "scanner_v2", "online", "aa:bb:cc:dd:ee:11", "192.0.2.11",
		nil, ptr(time.Now().AddDate(0, 0, -2)), ptr(time.Now().Add(-61*time.Minute)))
	insertDevice(t, conn, "newcomer", "scanner_v2", "online", "bb:bb:bb:bb:bb:06", "192.0.2.11",
		nil, nil, nil)

	newSvc(t, conn).runOnce(ctx)

	archived, _, _ := deviceState(t, conn, ghost)
	require.True(t, archived, "restore must be skipped while an active device holds the recorded IP")
	require.Equal(t, int64(0), countEvents(t, conn, ghost, EventRestored, TriggerAutoRestore))
}
