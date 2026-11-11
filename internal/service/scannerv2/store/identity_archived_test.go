// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package store

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Archived rows and the identity resolver (#737): an archived device's
// ip_address is its LAST RECORDED address — history, not a live claim. The
// (ip, network) slot logic must treat archived rows as invisible (a new
// occupant of the address starts its own record instead of morphing — or
// being blocked by — the archive entry), while the MAC-primary path still
// finds archived rows (that is how an archived device returns). The partial
// unique index backs this: slot uniqueness holds among LIVE rows only.

// seedArchivedRow seeds a device row already in the archive.
func seedArchivedRow(t *testing.T, db *sql.DB, ip, mac string, networkID sql.NullInt64) int64 {
	t.Helper()
	id := seedDeviceRow(t, db, ip, mac, networkID)
	_, err := db.Exec(`UPDATE devices SET archived_at = ? WHERE id = ?`,
		time.Now().UTC().Add(-48*time.Hour), id)
	if err != nil {
		t.Fatalf("archive seed row: %v", err)
	}
	return id
}

// The partial slot index is part of the schema contract: fresh databases
// create the unique (ip, network) constraint scoped to LIVE rows only.
func TestSchema_SlotIndexIsLiveOnly(t *testing.T) {
	repo, _, _, _ := resolveRepo(t, 1)
	var sqlText string
	err := repo.db.QueryRow(
		`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_devices_ip_network'`,
	).Scan(&sqlText)
	require.NoError(t, err)
	require.Contains(t, sqlText, "WHERE archived_at IS NULL",
		"the (ip, network) unique index must be scoped to live rows")
}

// A MAC-less newcomer at an ARCHIVED record's address starts a fresh row —
// the archive entry is history, not the slot's live identity.
func TestResolveDeviceIdentity_ArchivedIPOnlyRow_NewOccupantIsNew(t *testing.T) {
	repo, nid, db, ctx := resolveRepo(t, 1)
	tombstone := seedArchivedRow(t, db, "10.0.0.5", "", nid)
	res, err := repo.ResolveDeviceIdentity(ctx, "", "10.0.0.5", nid)
	require.NoError(t, err)
	require.True(t, res.IsNew, "archived record must not be matched by the (ip, network) slot")
	require.Zero(t, res.TargetID)
	// The coexistence contract: the newcomer's INSERT succeeds while the
	// archived row keeps the address (partial unique index).
	newID := seedDeviceRowWithUUID(t, db, "10.0.0.5", "", nid, "seed-archived-coexist")
	require.NotEqual(t, tombstone, newID)
	var archIP string
	require.NoError(t, db.QueryRow(`SELECT ip_address FROM devices WHERE id = ?`, tombstone).Scan(&archIP))
	require.Equal(t, "10.0.0.5", archIP, "the archived record keeps its last recorded IP")
}

// A never-seen MAC at an archived record's address must NOT adopt the record
// (宁空勿错: the unknown stays what it was) — a new row for the specific MAC
// instead.
func TestResolveDeviceIdentity_ArchivedIPOnlyRow_NeverSeenMAC_NoAdoption(t *testing.T) {
	repo, nid, db, ctx := resolveRepo(t, 1)
	tombstone := seedArchivedRow(t, db, "10.0.0.5", "", nid)
	res, err := repo.ResolveDeviceIdentity(ctx, "cc:cc:cc:cc:cc:03", "10.0.0.5", nid)
	require.NoError(t, err)
	require.True(t, res.IsNew, "a specific new MAC must not adopt an archive record")
	require.Zero(t, res.TargetID)
	// INSERT succeeds: the archived row does not hold the live slot.
	newID := seedDeviceRow(t, db, "10.0.0.5", "cc:cc:cc:cc:cc:03", nid)
	require.NotEqual(t, tombstone, newID)
}

// A never-seen MAC at an archived MAC-FUL record's address must not take the
// archived row over either — same doctrine, stronger identity on the line.
func TestResolveDeviceIdentity_ArchivedMACRow_NeverSeenMAC_NoTakeOver(t *testing.T) {
	repo, nid, db, ctx := resolveRepo(t, 1)
	tombstone := seedArchivedRow(t, db, "10.0.0.5", "aa:bb:cc:dd:ee:01", nid)
	res, err := repo.ResolveDeviceIdentity(ctx, "cc:cc:cc:cc:cc:03", "10.0.0.5", nid)
	require.NoError(t, err)
	require.True(t, res.IsNew, "archived records are never takeover targets")
	require.Zero(t, res.TargetID)
	_ = tombstone
	_ = seedDeviceRow(t, db, "10.0.0.5", "cc:cc:cc:cc:cc:03", nid)
}

// The return path is untouched: the archived device's OWN MAC matches the
// archived row — at the recorded IP (plain match → the archive engine's
// restore clock starts) and at a NEW free IP (roam; the record follows its
// device, "last recorded IP" updates).
func TestResolveDeviceIdentity_ArchivedMACRow_ReturnViaMAC(t *testing.T) {
	repo, nid, db, ctx := resolveRepo(t, 1)
	tombstone := seedArchivedRow(t, db, "10.0.0.5", "aa:bb:cc:dd:ee:01", nid)

	res, err := repo.ResolveDeviceIdentity(ctx, "aa:bb:cc:dd:ee:01", "10.0.0.5", nid)
	require.NoError(t, err)
	require.Equal(t, tombstone, res.TargetID, "same-IP return matches the archived row")
	require.False(t, res.Roamed)

	res, err = repo.ResolveDeviceIdentity(ctx, "aa:bb:cc:dd:ee:01", "10.0.0.9", nid)
	require.NoError(t, err)
	require.Equal(t, tombstone, res.TargetID, "new-IP return still matches by MAC")
	require.True(t, res.Roamed, "the archived record follows its device")
}

// A MAC-ful newcomer at an archived record's address also coexists (the
// newcomer's MAC is unseen; the slot is free among live rows).
func TestResolveDeviceIdentity_ArchivedMACRow_NewMACCoexists(t *testing.T) {
	repo, nid, db, ctx := resolveRepo(t, 1)
	tombstone := seedArchivedRow(t, db, "10.0.0.5", "aa:bb:cc:dd:ee:01", nid)
	res, err := repo.ResolveDeviceIdentity(ctx, "cc:cc:cc:cc:cc:03", "10.0.0.5", nid)
	require.NoError(t, err)
	require.True(t, res.IsNew)
	newID := seedDeviceRow(t, db, "10.0.0.5", "cc:cc:cc:cc:cc:03", nid)
	var archIP, archMAC string
	require.NoError(t, db.QueryRow(`SELECT ip_address, mac_address FROM devices WHERE id = ?`, tombstone).
		Scan(&archIP, &archMAC))
	require.Equal(t, "10.0.0.5", archIP, "history preserved")
	require.Equal(t, "aa:bb:cc:dd:ee:01", archMAC, "no MAC hijack")
	require.NotEqual(t, tombstone, newID)
}

// LIVE rows keep the strict slot uniqueness (regression guard on the
// pre-existing behavior the partial index must preserve).
func TestResolveDeviceIdentity_LiveHolderStillTakenOver(t *testing.T) {
	repo, nid, db, ctx := resolveRepo(t, 1)
	priorID := seedDeviceRow(t, db, "10.0.0.100", "aa:bb:cc:dd:ee:01", nid)
	holderID := seedDeviceRow(t, db, "10.0.0.5", "bb:bb:bb:bb:bb:02", nid)
	res, err := repo.ResolveDeviceIdentity(ctx, "aa:bb:cc:dd:ee:01", "10.0.0.5", nid)
	require.NoError(t, err)
	require.Equal(t, holderID, res.TargetID)
	require.Equal(t, priorID, res.ReplacedID)
	// And a direct live-slot INSERT still collides (unique among live rows).
	_, err = db.Exec(`INSERT INTO devices (name, type, ip_address, mac_address, status, scan_source,
		scan_attributes, network_id, device_uuid, created_at, updated_at)
		VALUES ('dupe', 'other', '10.0.0.5', 'dd:dd:dd:dd:dd:04', 'online', 'scanner_v2', '{}', ?,
		'seed-dupe', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`, nid)
	require.Error(t, err, "two live rows cannot hold the same (ip, network) slot")
	require.True(t, strings.Contains(strings.ToLower(err.Error()), "unique"))
}
