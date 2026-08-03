// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package runner

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/changedetect"
	"mibee-steward/internal/db"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/testutil"
)

// setupScanAttrsTestDB mirrors setupTypeTestDB but lives here to keep the
// scan_attributes merge tests self-contained.
func setupScanAttrsTestDB(t *testing.T) (*Runner, *sql.DB) {
	t.Helper()
	conn, err := testutil.SetupTestDBFromSchema()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	queries := db.New(conn)
	net, err := queries.CreateNetwork(context.Background(), db.CreateNetworkParams{Name: "merge-test-net"})
	require.NoError(t, err)
	nid := sql.NullInt64{Int64: net.ID, Valid: true}
	rn := New(nil, queries, conn, nil, 0, nil)
	rn.networkID = nid
	rn.SetChangeRecorder(changedetect.NewDBRecorder(queries, nil, 0, nil))
	return rn, conn
}

// reportWith builds a HostReport with the given Fields + Evidence, alive.
func reportWith(ip string, fields map[string]string, evidence ...scannerv2.Evidence) scannerv2.HostReport {
	rep := scannerv2.HostReport{IP: ip, Alive: true}
	rep.Device.Fields = fields
	rep.Evidence = evidence
	return rep
}

// TestScanAttributes_MergePreservesHostname is the core regression guard for
// issue #20 candidate fix C: a SHALLOW active scan (one that collected no
// hostname this cycle) must NOT erase a hostname an EARLIER scan (or passive
// discovery) wrote into scan_attributes. Pre-fix the UPDATE was
// `scan_attributes = ?` (blind overwrite); now it's json_patch, so omitted keys
// in the new blob survive.
func TestScanAttributes_MergePreservesHostname(t *testing.T) {
	rn, conn := setupScanAttrsTestDB(t)
	ctx := context.Background()
	const ip = "192.168.63.20"

	// Scan 1: a deep scan that collected a hostname via mDNS + vendor + ports.
	_, _ = rn.applyDeviceBridge(ctx, reportWith(ip,
		map[string]string{"node_hostname": "MICKEYBEESSD", "inferred_brand": "Apache"},
		scannerv2.Evidence{Kind: "mdns", RawData: map[string]string{"hostname": "MICKEYBEESSD"}},
	), rn.networkID, "")

	var attrs1 string
	require.NoError(t, conn.QueryRow(`SELECT scan_attributes FROM devices WHERE ip_address=?`, ip).Scan(&attrs1))
	require.Contains(t, attrs1, `"hostname":"MICKEYBEESSD"`, "deep scan wrote the hostname")

	// Scan 2: a SHALLOW scan that found the host alive but collected NO hostname
	// (no mDNS response, no rDNS, SNMP off). This is the scenario that used to
	// wipe scan_attributes.hostname. Fields intentionally carry only a brand.
	_, _ = rn.applyDeviceBridge(ctx, reportWith(ip,
		map[string]string{"inferred_brand": "Apache"}, // no node_hostname, no sys_name
		// no evidence at all
	), rn.networkID, "")

	var attrs2 string
	require.NoError(t, conn.QueryRow(`SELECT scan_attributes FROM devices WHERE ip_address=?`, ip).Scan(&attrs2))
	require.Contains(t, attrs2, `"hostname":"MICKEYBEESSD"`,
		"shallow scan must NOT erase the hostname collected earlier (json_patch preserves omitted keys)")

	// And the deep scan's vendor is preserved too (it was omitted from scan 2).
	require.Contains(t, attrs2, `"vendor"`, "vendor from the deep scan survives the shallow overwrite")
}

// TestScanAttributes_MergeUpdatesPresentFields confirms the merge isn't
// purely additive: a field the new scan DID collect overwrites the old value
// (so a hostname change, a port closing, etc. is reflected). Without this the
// merge would freeze stale data.
func TestScanAttributes_MergeUpdatesPresentFields(t *testing.T) {
	rn, conn := setupScanAttrsTestDB(t)
	ctx := context.Background()
	const ip = "192.168.63.30"

	// Scan 1: hostname = OLD-NAME.
	_, _ = rn.applyDeviceBridge(ctx, reportWith(ip,
		map[string]string{"node_hostname": "OLD-NAME"},
	), rn.networkID, "")

	// Scan 2: hostname changed to NEW-NAME (device was renamed).
	_, _ = rn.applyDeviceBridge(ctx, reportWith(ip,
		map[string]string{"node_hostname": "NEW-NAME"},
	), rn.networkID, "")

	var attrs string
	require.NoError(t, conn.QueryRow(`SELECT scan_attributes FROM devices WHERE ip_address=?`, ip).Scan(&attrs))
	require.Contains(t, attrs, `"hostname":"NEW-NAME"`, "a present field in the new scan overwrites the old")
	require.NotContains(t, attrs, "OLD-NAME", "the stale value is gone, not merged in alongside")
}

// TestScanAttributes_OpenPortsReplaceNotUnion guards the slice semantics at the
// devices.open_ports column (independent of scan_attributes JSON): open_ports is
// whole-replaced each scan (buildExistingUpdate `open_ports = ?`), so a port
// absent from the latest scan must not linger from an earlier one.
func TestScanAttributes_OpenPortsReplaceNotUnion(t *testing.T) {
	rn, conn := setupScanAttrsTestDB(t)
	ctx := context.Background()
	const ip = "192.168.63.40"

	// Scan 1: ports 80 + 22 in the evidence.
	_, _ = rn.applyDeviceBridge(ctx, reportWith(ip,
		map[string]string{},
		scannerv2.Evidence{Kind: "port", Port: 80, RawData: map[string]string{"service": "http"}},
		scannerv2.Evidence{Kind: "port", Port: 22, RawData: map[string]string{"service": "ssh"}},
	), rn.networkID, "")

	// Scan 2: only port 80.
	_, _ = rn.applyDeviceBridge(ctx, reportWith(ip,
		map[string]string{},
		scannerv2.Evidence{Kind: "port", Port: 80, RawData: map[string]string{"service": "http"}},
	), rn.networkID, "")

	var openPorts string
	require.NoError(t, conn.QueryRow(`SELECT open_ports FROM devices WHERE ip_address=?`, ip).Scan(&openPorts))
	// Port 22 was only in scan 1. Whatever scan 2 wrote, 22 must NOT appear —
	// the column tracks the latest scan, not a union.
	require.NotContains(t, openPorts, `"port":22`,
		"a port absent from the latest scan must not linger from an earlier scan (replace, not union)")
}

// TestScanAttributes_MACFlagsDerivedFromMAC verifies that the MAC bit flags
// (mac_is_locally_administered / mac_is_multicast) are derived from the observed
// MAC and persisted into scan_attributes. The flags are computed from attr.MAC
// AFTER both the Fields["mac"] path and the mac-kind evidence path fold in, so
// they reflect whichever MAC was actually recorded. Both flags are neutral
// factual bit reads (IEEE 802 / RFC 7042); neither changes device identity.
func TestScanAttributes_MACFlagsDerivedFromMAC(t *testing.T) {
	rn, conn := setupScanAttrsTestDB(t)
	ctx := context.Background()

	cases := []struct {
		name             string
		mac              string
		wantLocallyAdmin bool
		wantMulticast    bool
	}{
		// U/L bit (0x02) set: low nibble of first octet has bit 0x2 — locally administered.
		{"locally administered 02", "02:11:22:33:44:55", true, false},
		{"locally administered 1a", "1a:bb:cc:dd:ee:ff", true, false},
		// Universally administered OUIs: U/L bit clear.
		{"universal bcad28", "bc:ad:28:11:22:33", false, false},
		// Multicast bit (0x01) set: low nibble odd.
		{"multicast 01005e", "01:00:5e:00:00:01", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip := "192.168.63.50"
			// Wipe devices between subtests so each MAC starts fresh.
			_, _ = conn.Exec(`DELETE FROM devices WHERE ip_address=?`, ip)
			_, _ = rn.applyDeviceBridge(ctx, reportWith(ip,
				map[string]string{"mac": c.mac},
				scannerv2.Evidence{Kind: "mac", RawData: map[string]string{"mac": c.mac, "vendor": "testvendor"}},
			), rn.networkID, "")

			var attrs string
			require.NoError(t, conn.QueryRow(`SELECT scan_attributes FROM devices WHERE ip_address=?`, ip).Scan(&attrs))

			if c.wantLocallyAdmin {
				require.Contains(t, attrs, `"mac_is_locally_administered":true`,
					"locally-administered MAC must set mac_is_locally_administered=true")
			} else {
				// omitempty: a false bool is omitted from JSON entirely.
				require.NotContains(t, attrs, `mac_is_locally_administered`,
					"universally-administered MAC must omit mac_is_locally_administered (omitempty)")
			}
			if c.wantMulticast {
				require.Contains(t, attrs, `"mac_is_multicast":true`,
					"multicast MAC must set mac_is_multicast=true")
			} else {
				require.NotContains(t, attrs, `mac_is_multicast`,
					"unicast MAC must omit mac_is_multicast (omitempty)")
			}
			// The MAC itself is always recorded regardless of the flags.
			require.Contains(t, attrs, `"mac":"`+c.mac+`"`, "MAC stored as observed attribute")
		})
	}
}

// TestScanAttributes_OUIFieldsRecorded verifies that the OUI prefix + vendor
// (factual IEEE registry data, kept SEPARATE from the device's self-declared
// brand) flow from mac-kind evidence into scan_attributes. These are
// unconditional factual fields — they are recorded even when a stronger
// SNMP/HTTP-derived brand is present (the two have different semantics: NIC
// silicon vendor vs device self-declared brand).
func TestScanAttributes_OUIFieldsRecorded(t *testing.T) {
	rn, conn := setupScanAttrsTestDB(t)
	ctx := context.Background()
	const ip = "192.168.63.60"

	// A report where the mac evidence carries OUI data AND a self-declared brand
	// (inferred_brand) — both should land in scan_attributes (different fields).
	_, _ = rn.applyDeviceBridge(ctx, reportWith(ip,
		map[string]string{
			"mac":            "bc:ad:28:11:22:33",
			"inferred_brand": "Hikvision (self-declared via SNMP)",
		},
		scannerv2.Evidence{Kind: "mac", RawData: map[string]string{
			"mac":        "bc:ad:28:11:22:33",
			"vendor":     "Hikvision Digital Technology",
			"oui_prefix": "BCAD28",
			"oui_vendor": "Hikvision Digital Technology",
		}},
	), rn.networkID, "")

	var attrs string
	require.NoError(t, conn.QueryRow(`SELECT scan_attributes FROM devices WHERE ip_address=?`, ip).Scan(&attrs))

	// OUI prefix + vendor recorded (factual registry data).
	require.Contains(t, attrs, `"oui_prefix":"BCAD28"`, "oui_prefix recorded from mac evidence")
	require.Contains(t, attrs, `"oui_vendor":"Hikvision Digital Technology"`, "oui_vendor recorded from mac evidence")
	// The self-declared brand wins for the top-level `vendor` field (it is
	// non-empty), but both coexist — oui_vendor is the NIC-chip vendor.
	require.Contains(t, attrs, `"vendor":"Hikvision (self-declared via SNMP)"`,
		"self-declared brand wins for top-level vendor, separate from oui_vendor")
}

// TestScanAttributes_ArpInterfaceRecorded guards #127: the local interface name
// that the ARP entry was learned on (/proc/net/arp column 6, captured by the ARP
// probe + post-scan MAC resolver) is surfaced under scan_attributes.extras so
// "which NIC on the center/agent saw this device" is answerable. It is a
// debugging/segmentation hint, not an identity signal — hence extras, not a
// typed top-level field.
func TestScanAttributes_ArpInterfaceRecorded(t *testing.T) {
	rn, conn := setupScanAttrsTestDB(t)
	ctx := context.Background()
	const ip = "192.168.63.61"

	// A mac evidence carrying the local interface name (the field the ARP probe
	// sets from /proc/net/arp's Device column).
	_, _ = rn.applyDeviceBridge(ctx, reportWith(ip,
		map[string]string{"mac": "bc:ad:28:11:22:44"},
		scannerv2.Evidence{Kind: "mac", RawData: map[string]string{
			"mac":    "bc:ad:28:11:22:44",
			"device": "br-lan",
		}},
	), rn.networkID, "")

	var attrs string
	require.NoError(t, conn.QueryRow(`SELECT scan_attributes FROM devices WHERE ip_address=?`, ip).Scan(&attrs))

	// arp_interface lands under extras (debugging signal, not a typed field).
	require.Contains(t, attrs, `"arp_interface":"br-lan"`,
		"local interface name from ARP evidence should be recorded under extras.arp_interface")
}

// TestScanAttributes_ArpInterfaceAbsentWhenNoDevice ensures the extras key is
// NOT fabricated when the ARP evidence carries no device name (e.g. a
// synthetic/mac-resolver-only evidence without a real /proc/net/arp row) —
// absence must stay absent rather than emitting an empty-string extra.
func TestScanAttributes_ArpInterfaceAbsentWhenNoDevice(t *testing.T) {
	rn, conn := setupScanAttrsTestDB(t)
	ctx := context.Background()
	const ip = "192.168.63.62"

	_, _ = rn.applyDeviceBridge(ctx, reportWith(ip,
		map[string]string{"mac": "bc:ad:28:11:22:55"},
		scannerv2.Evidence{Kind: "mac", RawData: map[string]string{
			"mac": "bc:ad:28:11:22:55",
			// no "device" key — common when the resolver only returned a MAC.
		}},
	), rn.networkID, "")

	var attrs string
	require.NoError(t, conn.QueryRow(`SELECT scan_attributes FROM devices WHERE ip_address=?`, ip).Scan(&attrs))
	require.NotContains(t, attrs, "arp_interface",
		"arp_interface must not appear when the ARP evidence carried no device name")
}
