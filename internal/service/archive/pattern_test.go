package archive

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
	"mibee-steward/internal/db"
	"mibee-steward/internal/testutil"
)

// addEvent writes an asset_archive_events row directly (test fixture: the
// learner consumes history, it must not generate it first).
func addEvent(t *testing.T, conn *sql.DB, deviceID int64, event, triggeredBy string, at time.Time) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(),
		`INSERT INTO asset_archive_events (device_id, event, triggered_by, detail, occurred_at)
		 VALUES (?, ?, ?, '{}', ?)`, deviceID, event, triggeredBy, at.UTC().Format(time.RFC3339Nano))
	require.NoError(t, err)
}

func devicePeriodic(t *testing.T, conn *sql.DB, id int64) (periodic int64, cycle float64) {
	t.Helper()
	require.NoError(t, conn.QueryRowContext(context.Background(),
		`SELECT periodic, periodic_cycle_days FROM devices WHERE id = ?`, id).Scan(&periodic, &cycle))
	return
}

// TestPattern_MonthlyArchivedDeviceRecognizedAndRestored: the canonical case —
// a device archived once that keeps blinking online roughly monthly. Three
// appearances spanning ≥60d with stable gaps → pattern learned, periodic flag
// set, device auto-restored out of the archive (trigger=pattern).
func TestPattern_MonthlyArchivedDeviceRecognizedAndRestored(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	now := time.Now()

	id := insertDevice(t, conn, "monthly", "scanner_v2", "offline", "aa:bb:cc:dd:ee:21", "192.0.2.21",
		ptr(now.AddDate(0, 0, -75)), ptr(now.AddDate(0, 0, -70)), nil)
	addEvent(t, conn, id, EventArchived, TriggerAutoOffline, now.AddDate(0, 0, -70))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.AddDate(0, 0, -62))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.AddDate(0, 0, -31))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.Add(-2*time.Hour))

	newSvc(t, conn).runOnce(ctx)

	archived, _, _ := deviceState(t, conn, id)
	require.False(t, archived, "a recognized monthly pattern must auto-restore out of the archive")
	periodic, cycle := devicePeriodic(t, conn, id)
	require.Equal(t, int64(1), periodic, "device must be flagged periodic")
	require.InDelta(t, 30.0, cycle, 5.0, "learned cycle ≈ 30d")
	require.Equal(t, int64(1), countEvents(t, conn, id, EventPatternLearned, TriggerPattern))
	require.Equal(t, int64(1), countEvents(t, conn, id, EventRestored, TriggerPattern))
	// And it must NOT get re-archived by the same tick's auto-archive pass.
	archived, _, _ = deviceState(t, conn, id)
	require.False(t, archived)
}

// TestPattern_InsufficientHistoryNotRecognized: appearances spanning only ~40d
// (< the 60d minimum) never trigger the learner — the device stays archived.
func TestPattern_InsufficientHistoryNotRecognized(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	now := time.Now()

	id := insertDevice(t, conn, "young", "scanner_v2", "offline", "aa:bb:cc:dd:ee:22", "192.0.2.22",
		ptr(now.AddDate(0, 0, -45)), ptr(now.AddDate(0, 0, -43)), nil)
	addEvent(t, conn, id, EventArchived, TriggerAutoOffline, now.AddDate(0, 0, -43))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.AddDate(0, 0, -40))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.AddDate(0, 0, -20))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.Add(-1*time.Hour))

	newSvc(t, conn).runOnce(ctx)

	archived, _, _ := deviceState(t, conn, id)
	require.True(t, archived, "40d of history (< 60d) must NOT be trusted")
	periodic, _ := devicePeriodic(t, conn, id)
	require.Equal(t, int64(0), periodic)
}

// TestPattern_ThresholdAtOrAboveCapNoExemption: with a per-device threshold of
// 45d (≥ the 30d cap) the smart exemption does not apply — the device archives
// normally even with a perfect monthly history.
func TestPattern_ThresholdAtOrAboveCapNoExemption(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	now := time.Now()

	// Archived device with a healthy pattern, but threshold 45d: the learn
	// pass must skip it (stays archived).
	id := insertDevice(t, conn, "high-thresh", "scanner_v2", "offline", "aa:bb:cc:dd:ee:23", "192.0.2.23",
		ptr(now.AddDate(0, 0, -75)), ptr(now.AddDate(0, 0, -70)), nil)
	_, err = conn.ExecContext(ctx, `UPDATE devices SET archive_offline_days_override = 45 WHERE id = ?`, id)
	require.NoError(t, err)
	addEvent(t, conn, id, EventArchived, TriggerAutoOffline, now.AddDate(0, 0, -70))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.AddDate(0, 0, -60))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.AddDate(0, 0, -30))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.Add(-2*time.Hour))

	newSvc(t, conn).runOnce(ctx)

	archived, _, _ := deviceState(t, conn, id)
	require.True(t, archived, "threshold 45d (≥ cap 30d) disables the exemption")
	periodic, _ := devicePeriodic(t, conn, id)
	require.Equal(t, int64(0), periodic)
}

// TestPattern_ExpiryClearsAndDoesNotRelearn: a periodic device absent longer
// than 2x its cycle loses the flag; the stale history must NOT be re-learned
// in the same (or a later) tick — the device must actually return once more
// before the pattern can be trusted again.
func TestPattern_ExpiryClearsAndDoesNotRelearn(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	now := time.Now()

	// Periodic device (flag pre-set, cycle 30d), last appearance 70d ago.
	id := insertDevice(t, conn, "expired", "scanner_v2", "offline", "aa:bb:cc:dd:ee:24", "192.0.2.24",
		ptr(now.AddDate(0, 0, -80)), ptr(now.AddDate(0, 0, -75)), nil)
	_, err = conn.ExecContext(ctx,
		`UPDATE devices SET periodic = 1, periodic_cycle_days = 30 WHERE id = ?`, id)
	require.NoError(t, err)
	addEvent(t, conn, id, EventArchived, TriggerAutoOffline, now.AddDate(0, 0, -75))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.AddDate(0, 0, -140))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.AddDate(0, 0, -110))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.AddDate(0, 0, -80))

	svc := newSvc(t, conn)
	svc.runOnce(ctx)

	periodic, _ := devicePeriodic(t, conn, id)
	require.Equal(t, int64(0), periodic, "absent 70d > 2x30d cycle: pattern must expire")
	require.Equal(t, int64(1), countEvents(t, conn, id, EventPatternCleared, TriggerPattern))
	archived, _, _ := deviceState(t, conn, id)
	require.True(t, archived, "after expiry the device archives normally (offline_since is old)")

	// A second tick must not resurrect the pattern from the stale history.
	svc.runOnce(ctx)
	periodic, _ = devicePeriodic(t, conn, id)
	require.Equal(t, int64(0), periodic, "stale history must not be re-learned")
}

// TestPattern_LearnerDisabled: archive.smart.disabled turns the whole
// mechanism off — no learning, no restore.
func TestPattern_LearnerDisabled(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	now := time.Now()

	id := insertDevice(t, conn, "no-smart", "scanner_v2", "offline", "aa:bb:cc:dd:ee:25", "192.0.2.25",
		ptr(now.AddDate(0, 0, -75)), ptr(now.AddDate(0, 0, -70)), nil)
	addEvent(t, conn, id, EventArchived, TriggerAutoOffline, now.AddDate(0, 0, -70))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.AddDate(0, 0, -60))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.AddDate(0, 0, -30))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.Add(-2*time.Hour))

	svc := New(db.New(conn), config.ArchiveConfig{
		OfflineDays: 7, RestoreOnlineMinutes: 60, SweepIntervalSeconds: 60,
		Smart: config.ArchiveSmartConfig{Disabled: true, MinHistoryDays: 60, MaxThresholdDays: 30},
	}, nil)
	svc.runOnce(ctx)

	archived, _, _ := deviceState(t, conn, id)
	require.True(t, archived, "disabled learner must leave the archive state alone")
	periodic, _ := devicePeriodic(t, conn, id)
	require.Equal(t, int64(0), periodic)
}

// TestPattern_ManualActionsExcludedFromEvidence: manual restores express
// human intent; only 1 auto appearance remains (<3) → no recognition.
func TestPattern_ManualActionsExcludedFromEvidence(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	now := time.Now()

	id := insertDevice(t, conn, "curated", "scanner_v2", "offline", "aa:bb:cc:dd:ee:26", "192.0.2.26",
		ptr(now.AddDate(0, 0, -75)), ptr(now.AddDate(0, 0, -70)), nil)
	addEvent(t, conn, id, EventArchived, TriggerAutoOffline, now.AddDate(0, 0, -70))
	addEvent(t, conn, id, EventRestored, TriggerManual, now.AddDate(0, 0, -60))
	addEvent(t, conn, id, EventRestored, TriggerManual, now.AddDate(0, 0, -30))
	addEvent(t, conn, id, EventRestored, TriggerManual, now.Add(-2*time.Hour))

	newSvc(t, conn).runOnce(ctx)

	periodic, _ := devicePeriodic(t, conn, id)
	require.Equal(t, int64(0), periodic, "manual restores are not device behavior")
}

// TestPattern_IrregularGapsNotRecognized: three appearances spanning 60d+ but
// with wildly irregular gaps (5d, 55d) → no pattern.
func TestPattern_IrregularGapsNotRecognized(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	now := time.Now()

	id := insertDevice(t, conn, "erratic", "scanner_v2", "offline", "aa:bb:cc:dd:ee:27", "192.0.2.27",
		ptr(now.AddDate(0, 0, -75)), ptr(now.AddDate(0, 0, -70)), nil)
	addEvent(t, conn, id, EventArchived, TriggerAutoOffline, now.AddDate(0, 0, -70))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.AddDate(0, 0, -65))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.AddDate(0, 0, -60))
	addEvent(t, conn, id, EventOnlineBlip, TriggerAutoRestore, now.Add(-2*time.Hour))

	newSvc(t, conn).runOnce(ctx)

	periodic, _ := devicePeriodic(t, conn, id)
	require.Equal(t, int64(0), periodic, "gaps 5d/55d are not a stable cycle")
}

// TestPattern_ActiveCandidateExemptAtDecisionPoint: a device with a learned
// history that comes up for archiving gets the periodic flag set at the
// decision point and stays in the asset library.
func TestPattern_ActiveCandidateExemptAtDecisionPoint(t *testing.T) {
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	now := time.Now()

	// Active (not archived) device, offline 10d (past the 7d threshold), with
	// a prior archive/return cycle proving a monthly rhythm.
	id := insertDevice(t, conn, "returning", "scanner_v2", "offline", "aa:bb:cc:dd:ee:28", "192.0.2.28",
		ptr(now.AddDate(0, 0, -10)), nil, nil)
	addEvent(t, conn, id, EventArchived, TriggerAutoOffline, now.AddDate(0, 0, -95))
	addEvent(t, conn, id, EventRestored, TriggerAutoRestore, now.AddDate(0, 0, -90))
	addEvent(t, conn, id, EventArchived, TriggerAutoOffline, now.AddDate(0, 0, -62))
	addEvent(t, conn, id, EventRestored, TriggerAutoRestore, now.AddDate(0, 0, -57))
	addEvent(t, conn, id, EventArchived, TriggerAutoOffline, now.AddDate(0, 0, -25))
	addEvent(t, conn, id, EventRestored, TriggerAutoRestore, now.AddDate(0, 0, -20))

	newSvc(t, conn).runOnce(ctx)

	archived, _, _ := deviceState(t, conn, id)
	require.False(t, archived, "candidate with a live monthly pattern must be exempt from archiving")
	periodic, cycle := devicePeriodic(t, conn, id)
	require.Equal(t, int64(1), periodic)
	require.InDelta(t, 35.0, cycle, 6.0, "learned cycle ≈ 35d (restores ~35d apart)")
}
