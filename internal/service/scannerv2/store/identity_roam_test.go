// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package store

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// TestApplyDeviceIdentity_RoamEvictsMaclessPlaceholder pins the #399-era roam
// retry: resolve marks Roamed while the target IP is free, a racing MAC-less
// scan then inserts a mac=” placeholder at that IP, and the apply-time roam
// UPDATE hits the (ip_address, network_id) unique constraint. The eviction
// path must DELETE the placeholder and retry successfully.
func TestApplyDeviceIdentity_RoamEvictsMaclessPlaceholder(t *testing.T) {
	repo, nid, conn, ctx := resolveRepo(t, 1)
	mac := "aa:bb:cc:dd:ee:01"
	devID := seedDeviceRow(t, conn, "10.0.0.5", mac, nid)

	res, err := repo.ResolveDeviceIdentity(ctx, mac, "10.0.0.9", nid)
	require.NoError(t, err)
	require.True(t, res.Roamed, ".9 is free at resolve time → roam")

	// Simulate the race: a MAC-less scan lands a placeholder at .9 between
	// resolve and apply.
	seedDeviceRow(t, conn, "10.0.0.9", "", nid)
	require.Equal(t, 2, countRows(t, conn, "SELECT COUNT(*) FROM devices"))

	_, err = repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
		TargetID: devID, Roamed: true,
		IP: "10.0.0.9", MAC: mac, NetworkID: nid,
	})
	require.NoError(t, err)

	// The placeholder was evicted and the real device relocated to .9, one
	// row total, still keyed by the original id.
	require.Equal(t, 1, countRows(t, conn, "SELECT COUNT(*) FROM devices"))
	var ip, macOut string
	require.NoError(t, conn.QueryRow(`SELECT ip_address, mac_address FROM devices WHERE id = ?`, devID).Scan(&ip, &macOut))
	require.Equal(t, "10.0.0.9", ip)
	require.Equal(t, mac, macOut)
}

// TestApplyDeviceIdentity_RoamRetryFailsOnRealHolder is the eviction path's
// guard rail: when the IP is held by a row with a REAL (non-empty) mac, the
// eviction DELETE must not remove it and the retry UPDATE fails the unique
// constraint again, the apply still returns the target id (non-fatal
// semantics) and the holder survives.
func TestApplyDeviceIdentity_RoamRetryFailsOnRealHolder(t *testing.T) {
	repo, nid, conn, ctx := resolveRepo(t, 1)
	mac := "aa:bb:cc:dd:ee:02"
	devID := seedDeviceRow(t, conn, "10.0.0.5", mac, nid)

	res, err := repo.ResolveDeviceIdentity(ctx, mac, "10.0.0.9", nid)
	require.NoError(t, err)
	require.True(t, res.Roamed)

	// A real-mac device occupies .9 (a scenario Resolve would classify as
	// replacement, but apply must tolerate whatever write it is handed).
	holderID := seedDeviceRow(t, conn, "10.0.0.9", "11:22:33:44:55:66", nid)

	_, err = repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
		TargetID: devID, Roamed: true,
		IP: "10.0.0.9", MAC: mac, NetworkID: nid,
	})
	require.NoError(t, err, "roam retry failure is logged, not returned")

	// Holder untouched (DELETE keys on mac=''), roaming device stayed at .5.
	var holderIP string
	require.NoError(t, conn.QueryRow(`SELECT ip_address FROM devices WHERE id = ?`, holderID).Scan(&holderIP))
	require.Equal(t, "10.0.0.9", holderIP)
	var roamIP string
	require.NoError(t, conn.QueryRow(`SELECT ip_address FROM devices WHERE id = ?`, devID).Scan(&roamIP))
	require.Equal(t, "10.0.0.5", roamIP)
}

// TestRecordServices_MergesDuplicateServicePort drives the (service, port)
// dedup-merge: two identities sharing the key merge metadata (first-write
// wins per key, new keys added) and keep the HIGHEST confidence, so the
// UNIQUE(ip, service, port) insert never warns.
func TestRecordServices_MergesDuplicateServicePort(t *testing.T) {
	repo, ctx := newRepo(t, Options{})
	const ip = "10.0.0.7"
	err := repo.RecordServices(ctx, ip, []scannerv2.ServiceIdentity{
		{Service: "http", Port: 80, Confidence: 0.6, Metadata: map[string]string{"server": "nginx", "keep": "first"}},
		{Service: "http", Port: 80, Confidence: 0.95, Metadata: map[string]string{"server": "apache", "extra": "new"}},
		{Service: "ssh", Port: 22, Confidence: 0.9},
	}, nil)
	require.NoError(t, err)

	var httpCount int
	require.NoError(t, repo.db.QueryRow(`SELECT COUNT(*) FROM host_services WHERE ip = ? AND service = 'http'`, ip).Scan(&httpCount))
	require.Equal(t, 1, httpCount, "duplicate (service, port) collapsed to one row")

	var metadata string
	var confidence float64
	require.NoError(t, repo.db.QueryRow(
		`SELECT metadata, confidence FROM host_services WHERE ip = ? AND service = 'http'`, ip).Scan(&metadata, &confidence))
	require.Contains(t, metadata, `"server":"nginx"`, "first-write metadata value wins over the second identity's")
	require.Contains(t, metadata, `"keep":"first"`, "first identity's own keys survive the merge")
	require.Contains(t, metadata, `"extra":"new"`, "keys only the second identity had are added")
	require.InDelta(t, 0.95, confidence, 0.0001, "merged row keeps the highest confidence")
}

// TestRecordNeighbors_ResolvesViaNetworkScopedIP covers the network-scoped
// branch of resolveDeviceID (repo NetworkID valid + device on that network):
// neighbors attach to the device by (ip, network_id) without falling through
// to the global IP lookup.
func TestRecordNeighbors_ResolvesViaNetworkScopedIP(t *testing.T) {
	repo, ctx := newRepo(t, Options{NetworkID: 1})
	conn := repo.db
	_, err := conn.Exec(`INSERT INTO networks (id, name, cidr, site, created_at, updated_at)
		VALUES (1, 'n', '10.0.0.0/24', 's', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	nid := sql.NullInt64{Int64: 1, Valid: true}
	devID := seedDeviceRow(t, conn, "10.0.0.3", "aa:bb:cc:dd:ee:03", nid)

	err = repo.RecordNeighbors(ctx, "10.0.0.3", []scannerv2.NeighborSpec{
		{NeighborMAC: "aa:bb:cc:dd:ee:99", Protocol: "LLDP", LocalPort: "eth0", RemotePort: "gi1/0/1", VLANTag: "10"},
	})
	require.NoError(t, err)

	var n int
	require.NoError(t, conn.QueryRow(`SELECT COUNT(*) FROM device_neighbors WHERE device_id = ?`, devID).Scan(&n))
	require.Equal(t, 1, n, "neighbor attached to the network-scoped device row")
}

// TestApplyDeviceIdentity_NewMACTakesOverOccupiedIPSlot pins the field-found
// gap (2026-09-29, center log "UNIQUE constraint failed: devices.ip_address,
// devices.network_id"): a scan reports a NEVER-SEEN MAC at an IP whose
// (ip, network) slot is held by a DIFFERENT-mac row. The MAC lookup misses,
// the empty-mac fallback misses (the holder has a real mac), and resolution
// used to conclude IsNew → the INSERT violated the unique index and the
// report was dropped. The ip-holder is the authority for its network slot
// (same doctrine as the replacement path): resolution must resolve to the
// holder row with TakeOver so apply force-overwrites its mac and identity.
func TestApplyDeviceIdentity_NewMACTakesOverOccupiedIPSlot(t *testing.T) {
	repo, nid, conn, ctx := resolveRepo(t, 1)
	holderMAC := "aa:bb:cc:dd:ee:21"
	holderID := seedDeviceRow(t, conn, "10.0.0.5", holderMAC, nid)

	// A brand-new mac shows up at the holder's IP.
	newMAC := "aa:bb:cc:dd:ee:22"
	res, err := repo.ResolveDeviceIdentity(ctx, newMAC, "10.0.0.5", nid)
	require.NoError(t, err)
	require.False(t, res.IsNew, "an occupied slot must never resolve as new")
	require.Equal(t, holderID, res.TargetID)
	require.True(t, res.TakeOver, "different-mac holder → takeover semantics")

	// Apply: the holder row is force-taken-over (mac overwritten, identity
	// filled when empty), no second row appears, nothing is marked offline
	// (there is no stale mac-matched row to supersede). JSON blobs are set as
	// the bridge always provides them (a malformed patch would fail the whole
	// UPDATE).
	_, err = repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
		TargetID: res.TargetID, TakeOver: true,
		IP: "10.0.0.5", MAC: newMAC, NetworkID: nid,
		Name: "new-device", Type: "embedded", Brand: "Raspberry Pi Foundation",
		OpenPortsJSON: "[]", DetectedServicesJSON: "[]",
		ScanAttributesJSON: "{}", TagsJSON: "{}",
	})
	require.NoError(t, err)

	require.Equal(t, 1, countRows(t, conn, "SELECT COUNT(*) FROM devices"))
	var macOut, brandOut, statusOut string
	require.NoError(t, conn.QueryRow(`SELECT mac_address, brand, status FROM devices WHERE id = ?`, holderID).Scan(&macOut, &brandOut, &statusOut))
	require.Equal(t, newMAC, macOut)
	require.Equal(t, "Raspberry Pi Foundation", brandOut)
	require.Equal(t, "online", statusOut)
}

// TestApplyDeviceIdentity_JunkBrandHealedOnRescan pins the junk-brand heal:
// the identity UPDATE is fill-when-empty, so a web-server banner name (nginx/
// apache/…, pre-denylist field data) or a letter-less junk value ("0,1,2")
// would otherwise stay the brand forever. When a rescan carries a real brand,
// those two junk classes are overwritten; a curated NON-junk brand still wins
// over scan-derived ones (user edits preserved).
func TestApplyDeviceIdentity_JunkBrandHealedOnRescan(t *testing.T) {
	repo, nid, conn, ctx := resolveRepo(t, 1)
	mac := "aa:bb:cc:dd:ee:31"
	devID := seedDeviceRow(t, conn, "10.0.0.5", mac, nid)
	setBrand := func(b string) {
		_, err := conn.Exec(`UPDATE devices SET brand = ? WHERE id = ?`, b, devID)
		require.NoError(t, err)
	}
	rescan := func(brand string) {
		_, err := repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
			TargetID: devID, IP: "10.0.0.5", MAC: mac, NetworkID: nid,
			Brand:         brand,
			OpenPortsJSON: "[]", DetectedServicesJSON: "[]", ScanAttributesJSON: "{}",
		})
		require.NoError(t, err)
	}
	brandOf := func() string {
		var b string
		require.NoError(t, conn.QueryRow(`SELECT brand FROM devices WHERE id = ?`, devID).Scan(&b))
		return b
	}

	setBrand("nginx")
	rescan("QNAP")
	require.Equal(t, "QNAP", brandOf(), "web-server junk brand must be healed by a real brand")

	setBrand("0,1,2")
	rescan("Apple")
	require.Equal(t, "Apple", brandOf(), "letter-less junk brand must be healed by a real brand")

	setBrand("Synology")
	rescan("QNAP")
	require.Equal(t, "Synology", brandOf(), "non-junk curated brand must NOT be overwritten by a scan")

	rescan("")
	require.Equal(t, "Synology", brandOf(), "empty scan brand must not clear or change anything")
}

// TestApplyDeviceIdentity_NICFailoverAliasNoFlap pins the #472 anti-flap: a
// multi-homed host (Ethernet + WiFi on one IP, alternating reports) used to
// trigger the replacement path back and forth every report — force-overwriting
// identity columns and marking its own other-NIC row offline each cycle. The
// first replacement records the displaced MAC as an alias on the ip-holder
// (scan_attributes.mac_aliases); from then on a report from an ALIAS mac
// resolves to the holder as a plain update (no ReplacedID churn).
func TestApplyDeviceIdentity_NICFailoverAliasNoFlap(t *testing.T) {
	repo, nid, conn, ctx := resolveRepo(t, 1)
	ip := "10.0.0.5"
	macEth := "aa:bb:cc:dd:ee:41" // row seeded at the ip (the "first" NIC)
	macWifi := "aa:bb:cc:dd:ee:42"
	holderID := seedDeviceRow(t, conn, ip, macEth, nid)

	rescan := func(mac string) scannerv2.IdentityResolution {
		res, err := repo.ResolveDeviceIdentity(ctx, mac, ip, nid)
		require.NoError(t, err)
		_, err = repo.ApplyDeviceIdentity(ctx, scannerv2.IdentityWrite{
			TargetID: res.TargetID, ReplacedID: res.ReplacedID, IsNew: res.IsNew,
			TakeOver: res.TakeOver, Roamed: res.Roamed,
			IP: ip, MAC: mac, NetworkID: nid, Brand: "Acme",
			OpenPortsJSON: "[]", DetectedServicesJSON: "[]", ScanAttributesJSON: "{}",
		})
		require.NoError(t, err)
		return res
	}

	// Cycle 1: the WiFi NIC reports at the occupied ip — its MAC was never
	// seen before, so this takes the TakeOver branch (force MAC onto the
	// holder). The holder's PREVIOUS ethernet MAC is recorded as an alias.
	res1 := rescan(macWifi)
	require.True(t, res1.TakeOver, "first foreign MAC at the slot must take over")
	require.Equal(t, holderID, res1.TargetID)

	// The holder now carries the displaced ethernet MAC as an alias.
	var attrs string
	require.NoError(t, conn.QueryRow(`SELECT scan_attributes FROM devices WHERE id=?`, holderID).Scan(&attrs))
	require.Contains(t, attrs, macEth, "replacement must record the displaced MAC as an alias")
	require.Contains(t, attrs, `"mac_aliases"`)

	// Cycle 2: the ethernet NIC reports again at the SAME ip. It is a known
	// alias of the holder — plain update, no second replacement.
	res2 := rescan(macEth)
	require.Zero(t, res2.ReplacedID, "alias MAC must not trigger another replacement")
	require.Equal(t, holderID, res2.TargetID, "alias report must resolve to the holder row")

	// And the holder's MAC/identity stay stable across the alternation.
	var mac, brand string
	require.NoError(t, conn.QueryRow(`SELECT mac_address, brand FROM devices WHERE id=?`, holderID).Scan(&mac, &brand))
	require.Equal(t, macWifi, mac, "holder keeps the last physical occupant's MAC")
	require.Equal(t, "Acme", brand)
	require.Equal(t, 1, countRows(t, conn, "SELECT COUNT(*) FROM devices"))
}
