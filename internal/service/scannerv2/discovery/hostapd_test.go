// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package discovery

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestHostapd_Parsers pins the two text formats the source understands: the
// hostapd ctrl protocol's key=value STA response and `iw dev X station dump`
// blocks.
func TestHostapd_Parsers(t *testing.T) {
	sta := parseHostapdSTA("addr=AA:BB:CC:DD:EE:FF\nsignal=-42\nconnected_time=3600\nssid=HomeNet\njunk-line-no-eq\n")
	require.Equal(t, "aa:bb:cc:dd:ee:ff", sta.mac)
	require.Equal(t, "-42", sta.signal)
	require.Equal(t, "3600", sta.connectTime)
	require.Equal(t, "HomeNet", sta.ssid)

	empty := parseHostapdSTA("")
	require.Empty(t, empty.mac)

	dump := parseIWStationDump(
		"Station AA:11:22:33:44:55 (on wlan0)\n" +
			"\tinactive time:\t30 ms\n" +
			"\tsignal:\t\t-51 dBm\n" +
			"\ttx bitrate:\t100.0 MBit/s\n" +
			"Station BB:22:33:44:55:66 (on wlan1)\n" +
			"\tsignal:\t\t-63 dBm\n" +
			"detail line before any station header\n")
	require.Len(t, dump, 2)
	require.Equal(t, "aa:11:22:33:44:55", dump["aa:11:22:33:44:55"].mac)
	require.Equal(t, "-51", dump["aa:11:22:33:44:55"].signal)
	require.Equal(t, "-63", dump["bb:22:33:44:55:66"].signal)

	require.Equal(t, "aa:11:22:33:44:55", extractIWStationMAC("Station AA:11:22:33:44:55 (on wlan0)"))
	require.Empty(t, extractIWStationMAC("not a station line"))
	require.Empty(t, extractIWStationMAC("Station "))

	require.Equal(t, "-51 dBm", iwValue("signal:\t\t-51 dBm", "signal:"))
	require.Empty(t, iwValue("tx bitrate:\t100", "signal:"))
}

// TestHostapd_SweepWith_EmitsAndDedupes drives the diff/emit path through the
// sweepWith seam. The coordinator consumer is NOT started: the
// coordinator's handle() drops IP-less events today, and hostapd events are
// pure L2 (MAC, no IP), so observing them at svc.Emit (the buffered events
// channel) is the faithful level for this source's contract. New STAs emit an
// event with signal/ssid/connected hints; repeats are suppressed by the
// source-level previous snapshot.
func TestHostapd_SweepWith_EmitsAndDedupes(t *testing.T) {
	svc := New(Config{}, nil, nil, nil, 0, nil, nil) // consumer NOT started
	src := NewHostapdSource(nil, time.Minute, svc, nil)
	require.Contains(t, src.String(), "hostapd(")

	recv := func() (NewHostEvent, bool) {
		select {
		case ev := <-svc.events:
			return ev, true
		case <-time.After(2 * time.Second):
			return NewHostEvent{}, false
		}
	}

	src.sweepWith(map[string]staInfo{
		"aa:bb:cc:00:00:01": {mac: "aa:bb:cc:00:00:01", signal: "-40", ssid: "net-a", connectTime: "10"},
	})
	ev, ok := recv()
	require.True(t, ok, "first sweep must emit the new STA")
	require.Equal(t, "aa:bb:cc:00:00:01", ev.MAC)
	require.Equal(t, "hostapd", ev.Source)
	require.Equal(t, "-40", ev.Hints["wifi_signal_dbm"])
	require.Equal(t, "net-a", ev.Hints["wifi_ssid"])
	require.Equal(t, "10", ev.Hints["wifi_connected_secs"])

	// Same MAC + a new one: only the new one emits.
	src.sweepWith(map[string]staInfo{
		"aa:bb:cc:00:00:01": {mac: "aa:bb:cc:00:00:01"},
		"aa:bb:cc:00:00:02": {mac: "aa:bb:cc:00:00:02"},
	})
	ev, ok = recv()
	require.True(t, ok, "the repeat MAC must be suppressed, the new one emitted")
	require.Equal(t, "aa:bb:cc:00:00:02", ev.MAC)

	// Empty sweep is a no-op (nothing emits).
	src.sweepWith(map[string]staInfo{})
	select {
	case ev := <-svc.events:
		t.Fatalf("empty sweep must not emit, got %+v", ev)
	default:
	}
}

// TestHostapd_QueryHostapdSocket_DialFailure pins the tolerated-failure
// contract: a socket path that cannot be dialed yields an empty result (the
// sweep falls back to iw), never an error. (A live ctrl-socket protocol
// exercise turned out to be too sensitive to unixgram autobind semantics
// across CI runners to be worth the flake risk; the response PARSING it
// feeds is pinned by TestHostapd_Parsers above.)
func TestHostapd_QueryHostapdSocket_DialFailure(t *testing.T) {
	src := NewHostapdSource(nil, time.Minute, nil, nil)
	require.Empty(t, src.queryHostapdSocket(filepath.Join(t.TempDir(), "nonexistent.sock")))

	// Glob-based socket discovery over a real (empty) dir, both outcomes.
	matches, err := ctrlSocketGlob(filepath.Join(t.TempDir(), "*"))
	require.NoError(t, err)
	require.Empty(t, matches)
}

// TestHostapd_QueryIW_ToleratesMissingBinary just pins that a missing/failing
// iw binary is a tolerated no-op on any platform (Windows: absent; CI: absent
// from the runner image), not a crash.
func TestHostapd_QueryIW_ToleratesMissingBinary(t *testing.T) {
	src := NewHostapdSource(nil, time.Minute, nil, nil)
	stas := src.queryIW("wlan0")
	if _, err := os.Stat("/sbin/iw"); err != nil && runtime.GOOS != "linux" {
		require.Empty(t, stas)
	}
}
