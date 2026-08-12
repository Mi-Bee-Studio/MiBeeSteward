// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.

package configdiff

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests pin the config-diff utility that underpins the device-config-
// backup feature (#137). The load-bearing contracts:
//   - identical configs → empty diff (the "don't persist a no-op version" gate),
//   - a changed config → a unified diff whose +/- lines reflect the change,
//   - the diff is deterministic and labels only the headers.

func TestDiff_IdenticalConfigsReturnEmpty(t *testing.T) {
	cfg := "hostname r1\ninterface eth0\n ip address 10.0.0.1/24\n"
	out, err := Diff("v1", cfg, "v2", cfg)
	require.NoError(t, err)
	require.Empty(t, out, "identical configs must yield no diff (no-op version gate)")
}

func TestDiff_ChangedConfigProducesUnifiedDiff(t *testing.T) {
	old := "hostname r1\ninterface eth0\n ip address 10.0.0.1/24\n"
	updated := "hostname r1\ninterface eth0\n ip address 10.0.0.2/24\n" // last octet changed

	out, err := Diff("v1", old, "v2", updated)
	require.NoError(t, err)
	require.NotEmpty(t, out)
	// A unified diff marks the removed old line with `-` and the added new with `+`.
	require.Contains(t, out, "- ip address 10.0.0.1/24")
	require.Contains(t, out, "+ ip address 10.0.0.2/24")
	// Headers carry the labels.
	require.Contains(t, out, "--- v1")
	require.Contains(t, out, "+++ v2")
	// Unchanged context (hostname) is preserved around the hunk.
	require.Contains(t, out, " hostname r1")
}

func TestDiff_AddedAndRemovedLines(t *testing.T) {
	old := "line-a\nline-b\nline-c\n"
	updated := "line-a\nline-c\nline-d\n" // b removed, d added

	out := MustDiff("o", old, "n", updated)
	require.Contains(t, out, "-line-b", "removed line marked")
	require.Contains(t, out, "+line-d", "added line marked")
	require.NotContains(t, out, "+line-a", "unchanged line not marked as added")
}

func TestDiff_EmptyOldConfig(t *testing.T) {
	out := MustDiff("", "", "v1", "hostname r1\n")
	require.Contains(t, out, "+hostname r1", "a first-ever capture is all additions")
}

func TestDiff_Deterministic(t *testing.T) {
	old, updated := "a\nb\n", "a\nc\n"
	first := MustDiff("o", old, "n", updated)
	for i := 0; i < 5; i++ {
		require.Equal(t, first, MustDiff("o", old, "n", updated), "diff must be deterministic")
	}
}

func TestChanged(t *testing.T) {
	require.False(t, Changed("same", "same"))
	require.True(t, Changed("a", "b"))
	require.True(t, Changed("a", "a\n")) // trailing newline is a real change
}

func TestHasChange(t *testing.T) {
	require.False(t, HasChange(""))
	require.True(t, HasChange("anything non-empty"))
	// Round-trip with Diff: a real change yields a non-empty diff that HasChange sees.
	out, _ := Diff("o", "a\n", "n", "b\n")
	require.True(t, HasChange(out))
}

// TestDiff_RealisticRunningConfig is a sanity check against a Cisco-IOS-shaped
// config edit: the diff isolates the changed stanza without noise elsewhere.
func TestDiff_RealisticRunningConfig(t *testing.T) {
	old := strings.Join([]string{
		"hostname core-sw",
		"!",
		"interface GigabitEthernet0/1",
		" description uplink",
		" switchport access vlan 10",
		"!",
		"end",
	}, "\n")
	updated := strings.Join([]string{
		"hostname core-sw",
		"!",
		"interface GigabitEthernet0/1",
		" description uplink-to-floor3",
		" switchport access vlan 30",
		"!",
		"end",
	}, "\n")

	out := MustDiff("running@t1", old, "running@t2", updated)
	require.Contains(t, out, "- description uplink")
	require.Contains(t, out, "+ description uplink-to-floor3")
	require.Contains(t, out, "- switchport access vlan 10")
	require.Contains(t, out, "+ switchport access vlan 30")
	// The unchanged hostname/end lines do NOT appear as +/- (only as context).
	require.NotContains(t, out, "+hostname core-sw")
	require.NotContains(t, out, "-hostname core-sw")
}
