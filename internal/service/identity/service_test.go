// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not accommodate;
// see LICENSE-COMMERCIAL.md.

package identity

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/metrics"
	"mibee-steward/internal/testutil"
)

var deviceIPCounter atomic.Uint64

func seedNetwork(t *testing.T, db *sql.DB, name string) int64 {
	t.Helper()
	res, err := db.Exec(`INSERT INTO networks (name, cidr) VALUES (?, ?)`, name, "192.0.2.0/24")
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

type deviceSeedOptions struct {
	name, hostname, serial, mac, brand, model, status string
	networkID                                         sql.NullInt64
	firstSeen, lastSeen                               time.Time
	archived                                          bool
	attrs                                             map[string]any
}

func seedDevice(t *testing.T, db *sql.DB, opts deviceSeedOptions) int64 {
	t.Helper()
	attrs := opts.attrs
	if attrs == nil {
		attrs = map[string]any{}
	}
	if opts.hostname != "" {
		attrs["hostname"] = opts.hostname
	}
	raw, err := json.Marshal(attrs)
	require.NoError(t, err)
	var archived any
	if opts.archived {
		archived = opts.lastSeen
	}
	res, err := db.Exec(`
INSERT INTO devices (device_uuid, name, type, brand, model, ip_address, mac_address,
                     serial_number, network_id, status, archived_at, first_seen, last_seen, scan_attributes)
VALUES (?, ?, 'server', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		uuid.NewString(), opts.name, opts.brand, opts.model, fmt.Sprintf("192.0.2.%d", 10+deviceIPCounter.Add(1)), opts.mac,
		opts.serial, opts.networkID, opts.status, archived, opts.firstSeen, opts.lastSeen, string(raw))
	require.NoError(t, err)
	id, err := res.LastInsertId()
	require.NoError(t, err)
	return id
}

func newService(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	db, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	svc := NewService(db)
	svc.now = func() time.Time { return now }
	return svc, db
}

func TestCandidatesNormalizeHostnameAcrossFQDNCaseAndPages(t *testing.T) {
	svc, db := newService(t)
	net := sql.NullInt64{Int64: seedNetwork(t, db, "lan-a"), Valid: true}
	start := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC)
	a := seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"a", "N305-Server.tail.example", "", "aa:bb:cc:dd:ee:01", "Acme", "N305", "online", net, start, end, false, nil})
	b := seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"b", "n305-server", "", "aa:bb:cc:dd:ee:02", "Acme", "N305", "online", net, start, end, false, nil})
	seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"c", "other-box", "", "aa:bb:cc:dd:ee:03", "Other", "", "online", net, start, end, false, nil})

	out, err := svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{Limit: 1, Offset: 0})
	require.NoError(t, err)
	require.Equal(t, 1, out.Total)
	require.Len(t, out.Candidates, 1)
	c := out.Candidates[0]
	require.Equal(t, a, c.DeviceA.ID)
	require.Equal(t, b, c.DeviceB.ID)
	require.Contains(t, c.Signals, domain.IdentitySignalHostname)
	require.True(t, c.TemporalOverlap)
	require.NotEmpty(t, c.Evidence)

	page2, err := svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{Limit: 1, Offset: 1})
	require.NoError(t, err)
	require.Empty(t, page2.Candidates)
}

func TestCandidatesSerialConfidenceAndCounterEvidence(t *testing.T) {
	svc, db := newService(t)
	net := sql.NullInt64{Int64: seedNetwork(t, db, "lan-a"), Valid: true}
	start := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC)
	seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"serial-a", "same-host", "SN-123", "aa:bb:cc:dd:ee:01", "Acme", "X", "online", net, start, end, false, nil})
	seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"serial-b", "same-host", "sn-123", "aa:bb:cc:dd:ee:02", "Acme", "X", "online", net, start, end, false, nil})
	seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"conflict-a", "conflict-host", "SN-A", "aa:bb:cc:dd:ee:03", "Acme", "X", "online", net, start, end, false, nil})
	seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"conflict-b", "conflict-host", "SN-B", "aa:bb:cc:dd:ee:04", "Acme", "X", "online", net, start, end, false, nil})

	out, err := svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{})
	require.NoError(t, err)
	require.Equal(t, 2, out.Total)
	require.Equal(t, domain.IdentityConfidenceHigh, out.Candidates[0].Confidence)
	require.Equal(t, domain.IdentityConfidenceLow, out.Candidates[1].Confidence)
	require.NotEmpty(t, out.Candidates[1].CounterEvidence)
}

func TestCandidatesMACAliasAndCertificate(t *testing.T) {
	svc, db := newService(t)
	net := sql.NullInt64{Int64: seedNetwork(t, db, "lan-a"), Valid: true}
	start := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC)
	a := seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"alias-a", "alias-host", "", "aa:bb:cc:dd:ee:01", "Acme", "X", "online", net, start, end, false, map[string]any{"mac_aliases": []string{"aa:bb:cc:dd:ee:02"}}})
	b := seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"alias-b", "alias-host", "", "aa:bb:cc:dd:ee:02", "Acme", "X", "online", net, start, end, false, nil})
	c := seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"cert-a", "cert-a", "", "aa:bb:cc:dd:ee:03", "Acme", "X", "online", net, start, end, false, nil})
	d := seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"cert-b", "cert-b", "", "aa:bb:cc:dd:ee:04", "Acme", "X", "online", net, start, end, false, nil})

	var uuidA, uuidB, uuidC, uuidD string
	require.NoError(t, db.QueryRow(`SELECT device_uuid FROM devices WHERE id=?`, a).Scan(&uuidA))
	require.NoError(t, db.QueryRow(`SELECT device_uuid FROM devices WHERE id=?`, b).Scan(&uuidB))
	require.NoError(t, db.QueryRow(`SELECT device_uuid FROM devices WHERE id=?`, c).Scan(&uuidC))
	require.NoError(t, db.QueryRow(`SELECT device_uuid FROM devices WHERE id=?`, d).Scan(&uuidD))
	certificate := strings.Repeat("A", 64)
	_, err := db.Exec(`INSERT INTO host_tls_certs (device_uuid, ip, port, cert_index, fingerprint_sha256, updated_at) VALUES (?, '192.0.2.10', 443, 0, ?, ?)`, uuidC, certificate, end)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO host_tls_certs (device_uuid, ip, port, cert_index, fingerprint_sha256, updated_at) VALUES (?, '192.0.2.10', 443, 0, ?, ?)`, uuidD, strings.ToLower(certificate), end)
	require.NoError(t, err)
	_ = uuidA
	_ = uuidB

	out, err := svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{})
	require.NoError(t, err)
	require.Equal(t, 2, out.Total)
	require.Equal(t, domain.IdentityConfidenceHigh, out.Candidates[0].Confidence)
	require.Contains(t, out.Candidates[0].Signals, domain.IdentitySignalMACAlias)
	require.Equal(t, domain.IdentityConfidenceMedium, out.Candidates[1].Confidence)
	require.Contains(t, out.Candidates[1].Signals, domain.IdentitySignalCertificate)
}

func TestScopeArchivedAndDeviceIdentity(t *testing.T) {
	svc, db := newService(t)
	net1 := sql.NullInt64{Int64: seedNetwork(t, db, "lan-a"), Valid: true}
	net2 := sql.NullInt64{Int64: seedNetwork(t, db, "lan-b"), Valid: true}
	start := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC)
	a := seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"scope-a", "scope-host", "SN-1", "aa:bb:cc:dd:ee:01", "Acme", "X", "online", net1, start, end, false, nil})
	seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"scope-b", "scope-host", "SN-1", "aa:bb:cc:dd:ee:02", "Acme", "X", "online", net1, start, end, false, nil})
	seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"other-net-a", "scope-host", "SN-1", "aa:bb:cc:dd:ee:03", "Acme", "X", "online", net2, start, end, false, nil})
	seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"other-net-b", "scope-host", "SN-1", "aa:bb:cc:dd:ee:04", "Acme", "X", "online", net2, start, end, false, nil})
	archived := seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"archived", "scope-host", "SN-1", "aa:bb:cc:dd:ee:05", "Acme", "X", "offline", net1, start, end, true, nil})

	_, err := db.Exec(`INSERT INTO device_network_presence (device_id, network_id, ip_address, first_seen, last_seen) VALUES (?, ?, '192.0.2.10', ?, ?)`, a, net1.Int64, start, end)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO device_network_presence (device_id, network_id, ip_address, first_seen, last_seen) VALUES (?, ?, '192.0.2.11', ?, ?)`, a, net2.Int64, start, end)
	require.NoError(t, err)

	scoped, err := svc.Candidates(context.Background(), domain.Scope{NetworkIDs: []int64{net1.Int64}}, CandidateFilter{})
	require.NoError(t, err)
	require.Equal(t, 1, scoped.Total)
	require.Equal(t, int64(2), scoped.Summary.TotalDevices, "archived rows must not enter the active review inventory")

	identity, err := svc.DeviceIdentity(context.Background(), a, domain.Scope{NetworkIDs: []int64{net1.Int64}})
	require.NoError(t, err)
	require.True(t, identity.Device.MultiHomed)
	require.False(t, identity.Device.Stale)
	require.Greater(t, identity.Device.EvidenceCoverage, 0.0)
	require.Len(t, identity.Candidates, 1)

	var archivedUUID string
	require.NoError(t, db.QueryRow(`SELECT device_uuid FROM devices WHERE id=?`, archived).Scan(&archivedUUID))
	archivedCertificate := strings.Repeat("C", 64)
	_, err = db.Exec(`INSERT INTO host_tls_certs (device_uuid, ip, port, cert_index, fingerprint_sha256, updated_at) VALUES (?, '192.0.2.10', 443, 0, ?, ?)`, archivedUUID, archivedCertificate, end)
	require.NoError(t, err)
	archivedIdentity, err := svc.DeviceIdentity(context.Background(), archived, domain.Scope{NetworkIDs: []int64{net1.Int64}})
	require.NoError(t, err)
	require.NotNil(t, archivedIdentity.Device.ArchivedAt)
	require.Equal(t, []string{archivedCertificate}, archivedIdentity.Device.CertFingerprints)
	require.Empty(t, archivedIdentity.Candidates)
}

func TestCandidatesRejectInvalidFiltersAndIgnoreIPAlone(t *testing.T) {
	svc, db := newService(t)
	net1 := sql.NullInt64{Int64: seedNetwork(t, db, "lan-a"), Valid: true}
	net2 := sql.NullInt64{Int64: seedNetwork(t, db, "lan-b"), Valid: true}
	now := time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC)
	seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"ip-a", "", "", "aa:bb:cc:dd:ee:01", "SameVendor", "SameModel", "online", net1, now, now, false, nil})
	seedDevice(t, db, struct {
		name, hostname, serial, mac, brand, model, status string
		networkID                                         sql.NullInt64
		firstSeen, lastSeen                               time.Time
		archived                                          bool
		attrs                                             map[string]any
	}{"ip-b", "", "", "aa:bb:cc:dd:ee:02", "SameVendor", "SameModel", "online", net2, now, now, false, nil})

	out, err := svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{})
	require.NoError(t, err)
	require.Zero(t, out.Total, "shared IP text/vendor/model without a stable signal must not create a candidate")
	_, err = svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{Offset: -1})
	require.ErrorIs(t, err, ErrInvalidFilter)
	_, err = svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{MinConfidence: "ultra"})
	require.ErrorIs(t, err, ErrInvalidFilter)
}

func TestCandidateDeviceIDsAnchorAcrossInventoryPages(t *testing.T) {
	svc, db := newService(t)
	net := sql.NullInt64{Int64: seedNetwork(t, db, "lan-a"), Valid: true}
	start := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC)
	a := seedDevice(t, db, deviceSeedOptions{"a", "paged-host", "SN-PAGE", "aa:bb:cc:dd:ee:01", "Acme", "X", "online", net, start, end, false, nil})
	b := seedDevice(t, db, deviceSeedOptions{"b", "paged-host", "SN-PAGE", "aa:bb:cc:dd:ee:02", "Acme", "X", "online", net, start, end, false, nil})
	seedDevice(t, db, deviceSeedOptions{"unrelated-a", "other-a", "SN-OTHER-A", "aa:bb:cc:dd:ee:03", "Acme", "X", "online", net, start, end, false, nil})
	seedDevice(t, db, deviceSeedOptions{"unrelated-b", "other-b", "SN-OTHER-B", "aa:bb:cc:dd:ee:04", "Acme", "X", "online", net, start, end, false, nil})

	out, err := svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{DeviceIDs: []int64{a}})
	require.NoError(t, err)
	require.Equal(t, 1, out.Total, "the matching row may be outside the requested device-id page")
	require.Equal(t, int64(4), out.Summary.TotalDevices, "summary remains the scoped inventory summary")
	require.Equal(t, a, out.Candidates[0].DeviceA.ID)
	require.Equal(t, b, out.Candidates[0].DeviceB.ID)

	medium, err := svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{
		DeviceIDs: []int64{a}, MinConfidence: domain.IdentityConfidenceMedium,
	})
	require.NoError(t, err)
	require.Equal(t, 1, medium.Total)

	none, err := svc.Candidates(context.Background(), domain.Scope{NetworkIDs: []int64{9999}}, CandidateFilter{DeviceIDs: []int64{a}})
	require.NoError(t, err)
	require.Zero(t, none.Total, "anchors must never widen the caller's network scope")
}

func TestSummaryStaleAndNonOverlappingCounterEvidence(t *testing.T) {
	svc, db := newService(t)
	net := sql.NullInt64{Int64: seedNetwork(t, db, "lan-a"), Valid: true}
	oldStart := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	oldEnd := time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	newStart := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	newEnd := time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC)
	seedDevice(t, db, deviceSeedOptions{"old", "same-host", "SN-A", "aa:bb:cc:dd:ee:01", "Acme", "X", "offline", net, oldStart, oldEnd, false, nil})
	seedDevice(t, db, deviceSeedOptions{"new", "same-host", "SN-B", "aa:bb:cc:dd:ee:02", "Acme", "X", "online", net, newStart, newEnd, false, nil})

	out, err := svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{})
	require.NoError(t, err)
	require.Equal(t, 1, out.Total)
	require.False(t, out.Candidates[0].TemporalOverlap)
	require.Contains(t, out.Candidates[0].CounterEvidence, "recorded activity windows do not overlap")
	require.Equal(t, 0.5, out.Summary.StaleRate)
	require.Equal(t, domain.IdentityConfidenceLow, out.Candidates[0].Confidence)
}

func TestCandidatesIgnoreMalformedIdentitySignals(t *testing.T) {
	svc, db := newService(t)
	net := sql.NullInt64{Int64: seedNetwork(t, db, "lan-a"), Valid: true}
	now := time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC)
	for _, name := range []string{"malformed-a", "malformed-b"} {
		id := seedDevice(t, db, deviceSeedOptions{
			name: name, hostname: "192.0.2.10", serial: "UNKNOWN", mac: "unknown",
			brand: "SameVendor", model: "SameModel", status: "online", networkID: net,
			firstSeen: now, lastSeen: now,
			attrs: map[string]any{"mac_aliases": []string{"not-a-mac"}},
		})
		var uuid string
		require.NoError(t, db.QueryRow(`SELECT device_uuid FROM devices WHERE id=?`, id).Scan(&uuid))
		_, err := db.Exec(`INSERT INTO host_tls_certs (device_uuid, ip, port, cert_index, fingerprint_sha256, updated_at) VALUES (?, '192.0.2.10', 443, 0, 'not-a-fingerprint', ?)`, uuid, now)
		require.NoError(t, err)
	}
	out, err := svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{})
	require.NoError(t, err)
	require.Zero(t, out.Total, "placeholder/malformed fields must not become trusted identity evidence")
}

func TestMetricsRefreshOnlyForUnfilteredGlobalInventory(t *testing.T) {
	svc, db := newService(t)
	net := sql.NullInt64{Int64: seedNetwork(t, db, "lan-a"), Valid: true}
	now := time.Date(2026, 11, 28, 8, 0, 0, 0, time.UTC)
	for i, name := range []string{"metric-a", "metric-b"} {
		seedDevice(t, db, deviceSeedOptions{name, "metric-host", "SN-METRIC", fmt.Sprintf("aa:bb:cc:dd:ee:%02d", i+1), "Acme", "X", "online", net, now, now, false, nil})
	}
	high := metrics.MibeeIdentityCandidates.WithLabelValues("high")
	high.Set(99)
	unknown := metrics.MibeeIdentityUnknownRate
	unknown.Set(0.75)

	_, err := svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{NetworkID: &net.Int64})
	require.NoError(t, err)
	require.Equal(t, float64(99), promtest.ToFloat64(high), "a network-filtered admin query is not the global inventory")
	require.Equal(t, 0.75, promtest.ToFloat64(unknown))

	_, err = svc.Candidates(context.Background(), domain.Scope{NetworkIDs: []int64{net.Int64}}, CandidateFilter{})
	require.NoError(t, err)
	require.Equal(t, float64(99), promtest.ToFloat64(high), "a restricted query must not overwrite global gauges")

	_, err = svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{})
	require.NoError(t, err)
	require.Equal(t, float64(1), promtest.ToFloat64(high))
	require.Zero(t, promtest.ToFloat64(unknown))

	_, err = db.Exec(`DELETE FROM devices`)
	require.NoError(t, err)
	empty, err := svc.Candidates(context.Background(), domain.Scope{Global: true}, CandidateFilter{})
	require.NoError(t, err)
	require.Zero(t, empty.Total)
	require.Zero(t, promtest.ToFloat64(high), "an empty global inventory must reset stale gauges")
	require.Zero(t, promtest.ToFloat64(unknown))
}
