// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 MiBee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ─── DNS log parsing ────────────────────────────────────────────────────────

func TestParseDnsmasqQuery_ClientQuery(t *testing.T) {
	// The dnsmasq --log-queries line shape for an actual client query.
	line := "Jan  1 12:00:00 router dnsmasq[1234]: query[A] example.com from 192.168.1.50"
	ip, domain := parseDnsmasqQuery(line)
	require.Equal(t, "192.168.1.50", ip)
	require.Equal(t, "example.com", domain)
}

func TestParseDnsmasqQuery_ReplyLineRejected(t *testing.T) {
	// A reply/forwarded line carries a name→ip mapping but NOT a querying host —
	// must NOT be emitted (no "query[...]" + "from <ip>" shape).
	line := "Jan  1 12:00:00 router dnsmasq[1234]: config example.com is 192.168.1.10"
	ip, domain := parseDnsmasqQuery(line)
	require.Empty(t, ip)
	require.Empty(t, domain)
}

func TestParseDnsmasqQuery_InterfaceRejected(t *testing.T) {
	// dnsmasq logs locally-originated queries as "from <iface>" — not a host.
	line := "Jan  1 12:00:00 router dnsmasq[1234]: query[A] localhost from lo"
	ip, domain := parseDnsmasqQuery(line)
	require.Empty(t, ip, "'from lo' is an interface, not a host")
	require.Empty(t, domain)
}

func TestParseDnsmasqQuery_NonDNSMASQLineRejected(t *testing.T) {
	// Unrelated syslog noise must not accidentally match.
	ip, domain := parseDnsmasqQuery("Jan 1 12:00:00 router sshd[5533]: Accepted publickey for root")
	require.Empty(t, ip)
	require.Empty(t, domain)
}

func TestLooksLikeIPv4(t *testing.T) {
	require.True(t, looksLikeIPv4("192.168.1.50"))
	require.True(t, looksLikeIPv4("10.0.0.1"))
	require.True(t, looksLikeIPv4("255.255.255.255"))
	require.False(t, looksLikeIPv4("lo"), "interface name")
	require.False(t, looksLikeIPv4("192.168.1.500"), "octet > 255")
	require.False(t, looksLikeIPv4("192.168.1"), "3 octets only")
	require.False(t, looksLikeIPv4("fe80::1"), "IPv6 not supported here")
	require.False(t, looksLikeIPv4("192.168.1.50.5"), "5 octets")
}

// TestDNSLog_TailFromEOFOnFirstSight confirms the source does NOT replay
// existing log history on the first sweep (it tails from EOF), but DOES emit
// queries that are appended AFTER the first sweep (true append, not rewrite).
func TestDNSLog_TailFromEOFOnFirstSight(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq.log")
	// Pre-existing content (history) — must be skipped on first sight.
	require.NoError(t, os.WriteFile(path, []byte(
		"Jan 1 00:00:00 r dnsmasq[1]: query[A] old.example.com from 192.168.1.99\n"), 0644))
	svc, sink, _, _ := newTestService(t, false)
	sink.isNew = true
	src := NewDNSLogSource(time.Minute, path, svc, nil)

	src.sweep() // first sweep: tail from EOF, no events from pre-existing content
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, 0, sink.count(), "pre-existing log history not replayed")

	// Append a new query AFTER the first sweep → must be emitted on next sweep.
	// Uses O_APPEND so the file grows (not rotates) — the offset-based tail sees
	// only the new bytes.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0644)
	require.NoError(t, err)
	_, err = f.WriteString("Jan 1 00:01:00 r dnsmasq[1]: query[A] new.example.com from 192.168.1.50\n")
	require.NoError(t, err)
	f.Close()

	src.sweep()
	time.Sleep(100 * time.Millisecond)
	reps := sink.snapshot()
	require.Len(t, reps, 1, "only the appended (post-first-sweep) query emitted")
	require.Equal(t, "192.168.1.50", reps[0].IP)
}

// ─── hostapd STA parsing ────────────────────────────────────────────────────

func TestParseHostapdSTA_FullEntry(t *testing.T) {
	resp := "addr=aa:bb:cc:dd:ee:ff\n" +
		"aid=1\n" +
		"capability=0x431\n" +
		"flags=[AUTH][ASSOC][AUTHORIZED]\n" +
		"connected_time=120\n" +
		"signal=-42\n" +
		"ssid=HomeNet\n" +
		"rx_bytes=12345\n"
	info := parseHostapdSTA(resp)
	require.Equal(t, "aa:bb:cc:dd:ee:ff", info.mac, "MAC lowercased")
	require.Equal(t, "-42", info.signal)
	require.Equal(t, "120", info.connectTime)
	require.Equal(t, "HomeNet", info.ssid)
}

func TestParseHostapdSTA_PartialEntry(t *testing.T) {
	// A minimal STA reply (only addr) — must still parse the MAC, empty rest.
	info := parseHostapdSTA("addr=11:22:33:44:55:66\n")
	require.Equal(t, "11:22:33:44:55:66", info.mac)
	require.Empty(t, info.signal)
	require.Empty(t, info.ssid)
}

// ─── iw station dump parsing ────────────────────────────────────────────────

func TestParseIWStationDump_TwoStations(t *testing.T) {
	out := "Station aa:bb:cc:dd:ee:01 (on wlan0)\n" +
		"\tinactive time:\t30 ms\n" +
		"\trx bytes:\t1000\n" +
		"\tsignal:\t-42 dBm\n" +
		"\ttx bitrate:\t300.0 MBit/s\n" +
		"\n" +
		"Station aa:bb:cc:dd:ee:02 (on wlan0)\n" +
		"\tinactive time:\t500 ms\n" +
		"\tsignal:\t-67 dBm\n"
	stas := parseIWStationDump(out)
	require.Len(t, stas, 2)
	require.Equal(t, "aa:bb:cc:dd:ee:01", stas["aa:bb:cc:dd:ee:01"].mac)
	require.Equal(t, "-42", stas["aa:bb:cc:dd:ee:01"].signal, "dBm unit stripped")
	require.Equal(t, "aa:bb:cc:dd:ee:02", stas["aa:bb:cc:dd:ee:02"].mac)
	require.Equal(t, "-67", stas["aa:bb:cc:dd:ee:02"].signal)
}

func TestParseIWStationDump_EmptyOutput(t *testing.T) {
	require.Empty(t, parseIWStationDump(""))
	require.Empty(t, parseIWStationDump("no stations here\n"))
}

func TestExtractIWStationMAC(t *testing.T) {
	require.Equal(t, "aa:bb:cc:dd:ee:ff",
		extractIWStationMAC("Station aa:bb:cc:dd:ee:ff (on wlan0)"))
	require.Empty(t, extractIWStationMAC("not a station line"))
}

// TestHostapd_NoSockets_NoOps confirms the source degrades gracefully when
// there's no hostapd ctrl socket AND iw is absent (a non-router/non-AP host) —
// no panic, no events, the documented no-op.
func TestHostapd_NoSockets_NoOps(t *testing.T) {
	// Point ctrlDir at a TempDir with nothing in it; interfaces at a bogus name.
	svc, sink, _, _ := newTestService(t, false)
	src := NewHostapdSource([]string{"nonexistent-wlan"}, time.Minute, svc, nil)
	src.ctrlDir = t.TempDir() // empty dir → no sockets globbed
	src.sweep()               // must not panic
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, 0, sink.count(), "no hostapd socket + bogus iw iface → no events")
}
