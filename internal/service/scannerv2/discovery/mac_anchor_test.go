// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// MAC-keyed anchoring (#522): an L2-witness sighting (LLDP/CDP chassis frame,
// NDP packet) of an unknown MAC synthesizes a MAC-anchored device row through
// the normal device bridge instead of being dropped — the chassis IS on the
// wire, only its L3 address is unknown yet. The report's IP is the anchor
// sentinel (unique per MAC, resolves by nothing else) so the bridge's
// identity path treats it as MAC-only. Sources that don't vouch L2 presence
// (hostapd associations) keep the enrich-existing-only doctrine.

func TestHandle_MACOnlyAnchor_UnknownChassisCreatesReport(t *testing.T) {
	for _, source := range []string{"lldp_frame", "cdp_frame", "passive:ebpf:nd"} {
		ctx := context.Background()
		sink := &recSink37{}
		svc := newDiscSvc37(sink, memoryDB(t))

		svc.handle(ctx, NewHostEvent{MAC: "aa:bb:cc:dd:ee:41", Source: source})

		require.Len(t, sink.reports, 1, "%s: unknown chassis must synthesize a report", source)
		rep := sink.reports[0]
		require.Equal(t, scannerv2.AnchorIP("aa:bb:cc:dd:ee:41"), rep.IP,
			"%s: report IP must be the anchor sentinel", source)
		require.Equal(t, "aa:bb:cc:dd:ee:41", rep.Device.Fields["mac"])
		require.True(t, rep.Alive)

		require.EqualValues(t, 1, svc.Status().Stats.MACOnlyAnchored, "%s", source)
		require.Equal(t, "anchored_mac", svc.lastEvents[0].Outcome, "%s", source)
	}
}

func TestHandle_MACOnlyAnchor_KnownChassisNoJunkEnrich(t *testing.T) {
	ctx := context.Background()
	conn := memoryDB(t)
	sink := &recSink37{}
	svc := newDiscSvc37(sink, conn)

	_, err := conn.Exec(`INSERT INTO devices (name, ip_address, mac_address, status, device_uuid)
		VALUES ('switch', '10.0.0.42', 'aa:bb:cc:dd:ee:42', 'online', 'seed-mac42')`)
	require.NoError(t, err)

	// The chassis is already inventoried: the neighbor-edge path owns topology,
	// nothing to enrich (no WiFi hints), nothing to create.
	svc.handle(ctx, NewHostEvent{MAC: "aa:bb:cc:dd:ee:42", Source: "lldp_frame"})
	require.Empty(t, sink.reports)

	var attrs string
	require.NoError(t, conn.QueryRow(
		`SELECT scan_attributes FROM devices WHERE mac_address = 'aa:bb:cc:dd:ee:42'`).Scan(&attrs))
	require.NotContains(t, attrs, "wifi", "a chassis re-sighting must not write a WiFi telemetry blob")
	require.Equal(t, "skipped_known", svc.lastEvents[0].Outcome)
}

func TestHandle_MACOnlyAnchor_NonWitnessSourceStillDrops(t *testing.T) {
	ctx := context.Background()
	sink := &recSink37{}
	svc := newDiscSvc37(sink, memoryDB(t))

	// hostapd associations don't vouch independent L2 presence the way a
	// chassis frame does; the no-fabrication doctrine stands for them.
	svc.handle(ctx, NewHostEvent{MAC: "de:ad:be:ef:00:02", Source: "hostapd"})
	require.Empty(t, sink.reports)
	require.Zero(t, svc.Status().Stats.MACOnlyAnchored)
	require.Equal(t, "skipped_unknown_mac", svc.lastEvents[0].Outcome)
}

// A second sighting of the same chassis inside the dedup window is one event,
// not two rows; after the window the bridge's MAC-primary identity merges it
// into the existing row anyway.
func TestHandle_MACOnlyAnchor_DedupWindowApplies(t *testing.T) {
	ctx := context.Background()
	sink := &recSink37{}
	svc := newDiscSvc37(sink, memoryDB(t))

	svc.handle(ctx, NewHostEvent{MAC: "aa:bb:cc:dd:ee:43", Source: "lldp_frame"})
	svc.handle(ctx, NewHostEvent{MAC: "aa:bb:cc:dd:ee:43", Source: "lldp_frame"})
	require.Len(t, sink.reports, 1, "repeat inside dedupTTL is suppressed")
}
