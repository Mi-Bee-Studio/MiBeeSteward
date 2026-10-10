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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// TestHostapd_SweepWith_WifiSink pins the AP→STA edge callback (#505): every
// sweep reports the FULL association list grouped by AP interface (not just
// new STAs — the edge's last_seen must refresh while a client stays
// associated), and the AP identity travels as the interface's own MAC so the
// caller can resolve the local end of the edge by MAC.
func TestHostapd_SweepWith_WifiSink(t *testing.T) {
	svc := New(Config{}, nil, nil, nil, 0, nil, nil) // consumer NOT started
	src := NewHostapdSource(nil, time.Minute, svc, nil)

	type assoc struct {
		apMAC  string
		iface  string
		staMAC []string
	}
	var got []assoc
	src.SetWifiNeighborSink(func(apMAC, iface string, staMACs []string) {
		got = append(got, assoc{apMAC, iface, append([]string(nil), staMACs...)})
	})

	src.sweepWith(map[string]staInfo{
		"aa:bb:cc:00:00:01": {mac: "aa:bb:cc:00:00:01", iface: "wlan0"},
		"aa:bb:cc:00:00:02": {mac: "aa:bb:cc:00:00:02", iface: "wlan0"},
		"aa:bb:cc:00:00:03": {mac: "aa:bb:cc:00:00:03", iface: "wlan1"},
	})
	require.Len(t, got, 2, "one callback per AP interface")
	var w0, w1 *assoc
	for i := range got {
		switch got[i].iface {
		case "wlan0":
			w0 = &got[i]
		case "wlan1":
			w1 = &got[i]
		}
	}
	require.NotNil(t, w0, "wlan0 group present")
	require.ElementsMatch(t, []string{"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"}, w0.staMAC)
	require.Equal(t, testIfaceMACFor("wlan0"), w0.apMAC, "AP identity is the interface's own MAC")
	require.NotNil(t, w1, "wlan1 group present")
	require.Equal(t, []string{"aa:bb:cc:00:00:03"}, w1.staMAC)

	// Repeat sweep with one STA dropped: the callback still fires with the
	// CURRENT list (refresh semantics), here just the remaining STA.
	got = nil
	src.sweepWith(map[string]staInfo{
		"aa:bb:cc:00:00:01": {mac: "aa:bb:cc:00:00:01", iface: "wlan0"},
	})
	require.Len(t, got, 1)
	require.Equal(t, []string{"aa:bb:cc:00:00:01"}, got[0].staMAC)
}

// testIfaceMACFor mirrors the source's AP-MAC resolution (net.InterfaceByName)
// so the test asserts the CONTRACT rather than a hard-coded address: both the
// source and this helper return the interface's MAC, or "" when the host has
// no such interface.
func testIfaceMACFor(iface string) string {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return ""
	}
	return ifc.HardwareAddr.String()
}

// TestHostapd_QuerySocket_RoundTrip pins the ctrl-socket client contract
// against a REAL unixgram server (#505): hostapd replies with sendto() to the
// address it received from, so the client must be bound to a name the server
// can see. A plain net.Dial unixgram client is nameless on Linux (the server's
// recvfrom yields an empty address and every reply is undeliverable) — this is
// the bug that made the hostapd-ctrl path silent against real APs, leaving
// only the iw fallback working. The server here replays the real protocol:
// STA-FIRST → one STA block, STA-NEXT → FAIL.
func TestHostapd_QuerySocket_RoundTrip(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("unixgram ctrl-socket protocol is Linux-only")
	}
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "wlan0")

	server, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sockPath, Net: "unixgram"})
	require.NoError(t, err)
	defer server.Close()

	staBlock := "addr=02:81:48:4e:d5:21\nsignal=-42\nconnected_time=3600\nssid=RigTestNet\n"
	go func() {
		for {
			buf := make([]byte, 128)
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			// Mirror what a real datagram server (hostapd, python) can do: a
			// peer with no address is unrepliable — sendto to an empty
			// sockaddr fails. Go's ReadFrom represents Go's own nameless
			// autobind peers as a non-nil addr with an EMPTY Name; that is
			// exactly the production bug this test pins.
			if ua, ok := addr.(*net.UnixAddr); !ok || ua.Name == "" {
				_ = n
				continue
			}
			reply := "FAIL\n"
			if strings.HasPrefix(string(buf[:n]), "STA-FIRST") {
				reply = staBlock
			}
			_, _ = server.WriteTo([]byte(reply), addr)
		}
	}()

	src := NewHostapdSource(nil, time.Minute, nil, nil)
	stas := src.queryHostapdSocket(sockPath)
	require.NotEmpty(t, stas, "client must receive the STA block (a reply requires a named client address)")
	info, ok := stas["02:81:48:4e:d5:21"]
	require.True(t, ok)
	require.Equal(t, "-42", info.signal)
	require.Equal(t, "RigTestNet", info.ssid)
	require.Equal(t, "wlan0", info.iface, "ctrl socket name attributes the AP interface")
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
