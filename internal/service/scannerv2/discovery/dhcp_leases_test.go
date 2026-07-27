// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
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

// writeLeaseFile writes the given dnsmasq-format content to a temp file and
// returns its path.
func writeLeaseFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "dhcp.leases")
	require.NoError(t, os.WriteFile(p, []byte(content), 0644))
	return p
}

// TestDHCPLeases_ReadLeases confirms the dnsmasq lease format is parsed
// correctly: 5-field rows, hostname de-quoted, MAC lowercased, and the
// hostname carried through. Also confirms expired leases are skipped and
// malformed/short rows are tolerated.
func TestDHCPLeases_ReadLeases(t *testing.T) {
	future := time.Now().Add(1 * time.Hour).Unix()
	past := time.Now().Add(-1 * time.Hour).Unix()
	content := joinLines(
		// valid, future expiry, with hostname
		itoa(future)+" AA:BB:CC:DD:EE:FF 192.168.1.50 phone-n13 *",
		// valid, hostname in quotes (some dnsmasq builds)
		itoa(future)+" 11:22:33:44:55:66 192.168.1.51 \"my-laptop\" 01:02:03",
		// expired — must be skipped
		itoa(past)+" 99:88:77:66:55:44 192.168.1.99 oldhost *",
		// hostname "*" — valid, just no name (client didn't send one)
		itoa(future)+" aa:bb:cc:00:00:01 192.168.1.52 * *",
		// malformed: only 2 fields — must be skipped, not crash
		"garbage row",
		// blank line + comment
		"",
		"# comment line",
	)
	path := writeLeaseFile(t, content)
	src := NewDHCPLeasesSource(time.Minute, path, nil, nil)

	leases, usedPath, err := src.readLeases()
	require.NoError(t, err)
	require.Equal(t, path, usedPath, "should use the explicit path")
	require.Len(t, leases, 3, "3 valid future leases (expired + malformed skipped)")

	byIP := map[string]dhcpLease{}
	for _, l := range leases {
		byIP[l.ip] = l
	}
	require.Equal(t, "phone-n13", byIP["192.168.1.50"].hostname)
	require.Equal(t, "aa:bb:cc:dd:ee:ff", byIP["192.168.1.50"].mac, "MAC lowercased")
	require.Equal(t, "my-laptop", byIP["192.168.1.51"].hostname, "hostname de-quoted")
	require.Equal(t, "192.168.1.52", byIP["192.168.1.52"].ip, "ip parsed")
	require.Equal(t, "*", byIP["192.168.1.52"].hostname, "star hostname preserved")
	require.NotContains(t, byIP, "192.168.1.99", "expired lease skipped")
}

// TestDHCPLeases_ReadLeases_ProbesDefaultPaths confirms that when leaseFile is
// empty, the constructor probes the conventional paths and returns
// os.ErrNotExist when none exist (the no-op-on-non-DHCP-host case).
func TestDHCPLeases_ReadLeases_ProbesDefaultPaths(t *testing.T) {
	// Point all conventional paths at a TempDir they don't exist in by
	// constructing with an empty string (which forces probing the real default
	// paths). On the test host none of them should exist, so readLeases returns
	// ErrNotExist — the documented no-op behavior on a non-DHCP host.
	src := NewDHCPLeasesSource(time.Minute, "", nil, nil)
	leases, _, err := src.readLeases()
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Nil(t, leases)
}

// TestDHCPLeases_Sweep_EmitsOnlyNew confirms the sweep diff: the first sweep
// emits every lease, the second identical sweep emits nothing (steady state is
// quiet). Uses the test Service helper + a capturing sink.
func TestDHCPLeases_Sweep_EmitsOnlyNew(t *testing.T) {
	future := time.Now().Add(1 * time.Hour).Unix()
	path := writeLeaseFile(t, joinLines(
		itoa(future)+" aa:bb:cc:dd:ee:01 192.168.1.10 host-a *",
		itoa(future)+" aa:bb:cc:dd:ee:02 192.168.1.11 host-b *",
	))
	svc, sink, _, _ := newTestService(t, false)
	sink.isNew = true // so Apply records every event (handle reaches sink)
	src := NewDHCPLeasesSource(time.Minute, path, svc, nil)

	src.sweep()
	time.Sleep(150 * time.Millisecond) // drain Emit → handle → sink
	require.Equal(t, 2, sink.count(), "first sweep emits both leases")
	// hostnames folded into the synthesized report's Fields via the dhcp hint.
	ips := map[string]bool{}
	for _, r := range sink.snapshot() {
		ips[r.IP] = true
	}
	require.True(t, ips["192.168.1.10"])
	require.True(t, ips["192.168.1.11"])

	// Second sweep — same file, nothing new.
	nBefore := sink.count()
	src.sweep()
	time.Sleep(150 * time.Millisecond)
	require.Equal(t, nBefore, sink.count(), "second identical sweep emits nothing")
}

// joinLines joins lines with newlines (helper to keep the table-driven content
// readable without trailing-newline ambiguity).
func joinLines(lines ...string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}

// itoa is a tiny int→string to avoid importing strconv just for the test
// lease-expiry timestamps.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
