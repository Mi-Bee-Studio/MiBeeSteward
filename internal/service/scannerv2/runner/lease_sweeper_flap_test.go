package runner

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
)

// TestLeaseSweeper_FlapDecaySuppressesPeriodicDevice is the regression test for
// the periodic-WiFi-IoT flap storm found during the post-#115 deploy soak.
//
// Real-world dynamics (observed on viomi-dishwasher / mipin-motion devices): the
// agent reports the device intermittently, so the lease flips stale→fresh with
// gaps on the order of the scan interval (well under flapStablePeriod). Each
// recovery's last_flap_at was set by the immediately-prior expire/recover, so
// now-last_flap_at < flapStablePeriod and the counter INCREMENTS, accumulating
// until it crosses flapThreshold — after which device_recovered is suppressed
// while the status column keeps tracking liveness. The OLD hard-reset design
// cleared the counter whenever now-last_flap_at crossed the stable period, which
// let a device whose gaps happened to straddle the boundary reset on every cycle.
//
// This test drives several close-spaced cycles (gaps < flapStablePeriod, so the
// counter increments) and asserts: (1) the status column tracks liveness, but
// (2) after the first few cycles device_recovered STOPS being emitted.
func TestLeaseSweeper_FlapDecaySuppressesPeriodicDevice(t *testing.T) {
	rn, queries, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	nid := sql.NullInt64{Int64: agentNetID, Valid: true}
	const ip = "192.168.62.99"

	// Seed: device online + a fresh snapshot.
	rn.applyDeviceBridge(ctx, reportFor(ip, "iot", "xiaomi", "aa:bb:cc:dd:ee:99"), nid, "agent-62")
	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{
		reportFor(ip, "iot", "xiaomi", "aa:bb:cc:dd:ee:99"),
	})

	// TTL short so "stale" is easy to reach; stable period stays the package default (30m).
	sweeper := NewLeaseSweeper(rn, time.Hour, time.Minute, nil)

	countRecovered := func() int {
		rows, _ := queries.ListChangeLog(ctx, db.ListChangeLogParams{
			Column1: 0, NetworkID: nil, Column3: 1, ChangeType: "device_recovered",
			Column5: 1, EntityType: "device", Limit: 1000, Offset: 0,
		})
		return len(rows)
	}
	deviceStatus := func() string {
		var s string
		conn.QueryRow(`SELECT status FROM devices WHERE ip_address=?`, ip).Scan(&s)
		return s
	}
	flapCount := func() int64 {
		var c int64
		conn.QueryRow(`SELECT flap_count FROM scan_snapshots WHERE network_id=? AND ip=?`, agentNetID, ip).Scan(&c)
		return c
	}
	// expireCycle simulates one full wake/sleep cycle with a CLOSE gap (well under
	// flapStablePeriod), so the recover branch increments the flap counter:
	//   1. lease stale (device asleep) → expireStale marks offline (increments flap_count).
	//   2. device wakes, lease fresh, device still offline → recoverFresh flips online.
	// Because both transitions stamp last_flap_at to ~now and the gap is small, the
	// recover path sees now-last_flap_at < flapStablePeriod → increments (no decay).
	expireCycle := func() {
		_, err := conn.ExecContext(ctx,
			`UPDATE scan_snapshots SET last_seen_at = ? WHERE network_id=? AND ip=?`,
			scannerv2.DBTime(time.Now().UTC().Add(-10*time.Minute)), agentNetID, ip)
		require.NoError(t, err)
		sweeper.sweepOnce(ctx) // expireStale: offline + flap_count++
		// Device wakes: refresh lease, keep device offline so recoverable query matches.
		_, err = conn.ExecContext(ctx,
			`UPDATE scan_snapshots SET last_seen_at = ? WHERE network_id=? AND ip=?`,
			scannerv2.DBTime(time.Now().UTC()), agentNetID, ip)
		require.NoError(t, err)
		_, err = conn.ExecContext(ctx, `UPDATE devices SET status='offline' WHERE ip_address=?`, ip)
		require.NoError(t, err)
		sweeper.sweepOnce(ctx) // recoverFresh: online + flap_count++ (close gap → increment)
	}

	// Drive enough cycles for flap_count to cross flapThreshold (each cycle adds 2:
	// one from expire, one from recover). After threshold, recoveries are suppressed.
	recoveredBefore := countRecovered()
	for i := 0; i < 6; i++ {
		expireCycle()
	}
	total := countRecovered()
	require.Equal(t, "online", deviceStatus(), "status column still tracks liveness")
	require.GreaterOrEqual(t, flapCount(), flapThreshold, "close-gaps accumulate flap_count past threshold")

	// We should NOT have gotten a device_recovered on every cycle. 6 cycles, each
	// would emit under the old design once reset; the suppress path must have cut
	// the later ones. Assert strictly fewer than 6 emissions after the seed.
	emittedThisRun := total - recoveredBefore
	require.Less(t, emittedThisRun, 6, "periodic device must not emit device_recovered every cycle")

	// Steady state: one more cycle produces NO new event (fully suppressed).
	lastTotal := countRecovered()
	expireCycle()
	require.Equal(t, lastTotal, countRecovered(), "steady-state periodic device fully suppressed")
	require.Equal(t, "online", deviceStatus(), "status still tracks liveness even when events are suppressed")
}

// TestLeaseSweeper_FlapDecay eventally clears for a device that genuinely stops
// flapping: after the device stays continuously online across several stable
// periods (no expires in between), the counter halves each pass and returns below
// the threshold, resuming normal event recording. This guards against the decay
// being too sticky (which would permanently hide a real recovery).
func TestLeaseSweeper_FlapDecayClearsAfterStable(t *testing.T) {
	rn, _, conn, _, agentNetID := setupLeaseTestDB(t)
	ctx := context.Background()
	nid := sql.NullInt64{Int64: agentNetID, Valid: true}
	const ip = "192.168.62.88"

	rn.applyDeviceBridge(ctx, reportFor(ip, "iot", "", "aa:bb:cc:dd:ee:88"), nid, "agent-62")
	rn.RecordAliveSnapshots(ctx, nid, 0, []scannerv2.HostReport{
		reportFor(ip, "iot", "", "aa:bb:cc:dd:ee:88"),
	})
	// Force the device into a known-flapping state: high flap_count + recent flap.
	_, err := conn.ExecContext(ctx,
		`UPDATE scan_snapshots SET flap_count = 8, last_flap_at = ? WHERE network_id=? AND ip=?`,
		scannerv2.DBTime(time.Now().UTC()), agentNetID, ip)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `UPDATE devices SET status='offline' WHERE ip_address=?`, ip)
	require.NoError(t, err)

	sweeper := NewLeaseSweeper(rn, time.Hour, time.Minute, nil)

	// Simulate the device now being genuinely stable: keep the lease fresh and
	// age last_flap_at past the stable period before each sweep, so each recovery
	// pass takes the DECAY branch (halves). A count of 8 → 4 → 2 → 1 → 0 across
	// four stable periods.
	for i := 0; i < 4; i++ {
		_, err = conn.ExecContext(ctx,
			`UPDATE scan_snapshots SET last_flap_at = ?, last_seen_at = ? WHERE network_id=? AND ip=?`,
			scannerv2.DBTime(time.Now().UTC().Add(-flapStablePeriod-time.Minute)), scannerv2.DBTime(time.Now().UTC()), agentNetID, ip)
		require.NoError(t, err)
		_, err = conn.ExecContext(ctx, `UPDATE devices SET status='offline' WHERE ip_address=?`, ip)
		require.NoError(t, err)
		sweeper.sweepOnce(ctx)
	}
	var c int64
	conn.QueryRow(`SELECT flap_count FROM scan_snapshots WHERE network_id=? AND ip=?`, agentNetID, ip).Scan(&c)
	require.Equal(t, int64(0), c, "flap_count decays to 0 after several stable periods")
}
