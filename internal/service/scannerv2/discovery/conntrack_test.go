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

// writeConntrackFile writes the given nf_conntrack-format content to a temp
// file and returns its path.
func writeConntrackFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "nf_conntrack")
	require.NoError(t, os.WriteFile(p, []byte(content), 0644))
	return p
}

// TestConntrack_ReadActiveLANHosts confirms the conntrack parser:
//   - extracts the LAN-side endpoint (src OR dst) of ESTABLISHED/ASSURED flows
//   - filters to the local CIDR (public IPs a device talks to are NOT emitted)
//   - skips non-established flows (TIME_WAIT / SYN_SENT aren't liveness)
//   - handles the LAN↔internet direction both ways (src=LAN and dst=LAN on reply)
func TestConntrack_ReadActiveLANHosts(t *testing.T) {
	// Two LAN hosts (.41 and .138) talking to the internet, one LAN↔LAN flow,
	// and one non-established flow from a third host that must be ignored.
	content := joinLines(
		// .41 → 142.250.187.78 (TCP established) — src is LAN
		"ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.62.41 dst=142.250.187.78 sport=54812 dport=443 [ASSURED] mark=0 use=2",
		// reply direction of the same flow — dst is LAN (must not double-count, it's the same IP)
		"ipv4 2 tcp 6 431999 ESTABLISHED src=142.250.187.78 dst=192.168.62.41 sport=443 dport=54812 [ASSURED] mark=0 use=2",
		// .138 → 1.1.1.1 (UDP assured DNS) — src is LAN
		"ipv4 2 udp 17 29 src=192.168.62.138 dst=1.1.1.1 sport=41220 dport=53 [ASSURED] mark=0 use=2",
		// LAN↔LAN: .41 ↔ .138 — both endpoints are LAN, both emitted (dedup'd in the map)
		"ipv4 2 tcp 6 299 ESTABLISHED src=192.168.62.41 dst=192.168.62.138 sport=44000 dport=22 [ASSURED] mark=0 use=1",
		// .200 → 8.8.8.8 but in TIME_WAIT (not established) — MUST be skipped
		"ipv4 2 tcp 6 119 TIME_WAIT src=192.168.62.200 dst=8.8.8.8 sport=55000 dport=443 [UNREPLIED] mark=0 use=1",
	)
	path := writeConntrackFile(t, content)
	src := newConntrackSourceWithPath("192.168.62.0/24", time.Minute, path, nil, nil)

	hosts, err := src.readActiveLANHosts()
	require.NoError(t, err)
	// Only .41 and .138 (each seen on multiple flows, dedup'd to 2 entries).
	require.Len(t, hosts, 2, "two distinct LAN hosts with established flows")
	require.True(t, hosts["192.168.62.41"], "LAN src of established flow emitted")
	require.True(t, hosts["192.168.62.138"], "LAN src of UDP-assured + LAN↔LAN flow emitted")
	require.False(t, hosts["192.168.62.200"], "TIME_WAIT flow must NOT count as liveness")
}

// TestConntrack_InvalidCIDR_EmitsNothing confirms a misconfigured CIDR degrades
// to a no-op (not a panic) — the source returns empty rather than emitting
// every public IP.
func TestConntrack_InvalidCIDR_EmitsNothing(t *testing.T) {
	content := joinLines(
		"ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.62.41 dst=142.250.187.78 sport=54812 dport=443 [ASSURED] mark=0 use=2",
	)
	path := writeConntrackFile(t, content)
	src := newConntrackSourceWithPath("not-a-cidr", time.Minute, path, nil, nil)
	// sweep() short-circuits when localNet is nil; readActiveLANHosts would
	// still work but sweep never calls it. Verify both: nil localNet + sweep
	// produces no Emit (using the test Service + sink).
	require.Nil(t, src.localNet, "invalid CIDR → nil localNet at construction")
	svc, sink, _, _ := newTestService(t, false)
	src.svc = svc
	src.sweep()
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, 0, sink.count(), "invalid-CIDR source emits nothing")
}

// TestConntrack_MissingFile_Tolerated confirms the no-op-on-non-router behavior:
// when /proc/net/nf_conntrack doesn't exist (host isn't a NAT gateway), sweep
// logs at debug and emits nothing — no crash, no noisy errors.
func TestConntrack_MissingFile_Tolerated(t *testing.T) {
	src := newConntrackSourceWithPath("192.168.62.0/24", time.Minute,
		filepath.Join(t.TempDir(), "does-not-exist"), nil, nil)
	svc, sink, _, _ := newTestService(t, false)
	src.svc = svc
	src.sweep() // must not panic
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, 0, sink.count(), "missing conntrack file → no events, no crash")
}

// TestConntrack_TokenParsing covers the tokenValue + containsToken helpers
// directly (the line-level extraction the parser depends on). Documents the
// [ASSURED] bracketed-token quirk the sweep check must account for.
func TestConntrack_TokenParsing(t *testing.T) {
	line := "ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.62.41 dst=142.250.187.78 sport=54812 [ASSURED] mark=0 use=2"
	require.Equal(t, "192.168.62.41", tokenValue(line, "src="))
	require.Equal(t, "142.250.187.78", tokenValue(line, "dst="))
	require.Equal(t, "54812", tokenValue(line, "sport="))
	require.Equal(t, "", tokenValue(line, "missing="))
	// ESTABLISHED is a bare state token — matched directly.
	require.True(t, containsToken(line, "ESTABLISHED"))
	// [ASSURED] is a bracketed token; a bare "ASSURED" is NOT present (the
	// sweep check looks for "[ASSURED]" for UDP flows, which carry no state
	// field, only the [ASSURED] marker).
	require.True(t, containsToken(line, "[ASSURED]"))
	require.False(t, containsToken(line, "ASSURED"))
}
