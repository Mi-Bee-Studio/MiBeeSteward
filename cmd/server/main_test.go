// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBindAddr pins the #288 follow-up: the OpenWrt docs instruct GL-firmware
// users to bind v6 via `server.host: "::"` (the v4-listener kernel workaround).
// The old fmt.Sprintf("%s:%d") concatenation turned that into ":::8090",
// which net.Listen rejects with "too many colons in address" — observed live
// on the MT2500 as a crash loop. net.JoinHostPort brackets IPv6 literals so
// every documented (and undocumented-but-reasonable) host value starts.
func TestBindAddr(t *testing.T) {
	cases := []struct {
		name string
		host string
		port int
		want string
	}{
		{"empty host is the dual-stack wildcard", "", 8090, ":8090"},
		{"v6 wildcard literal is bracketed", "::", 8090, "[::]:8090"},
		{"v4 wildcard unchanged", "0.0.0.0", 8080, "0.0.0.0:8080"},
		{"explicit v4 address unchanged", "192.168.63.176", 8090, "192.168.63.176:8090"},
		{"explicit v6 address is bracketed", "fd00::1", 8090, "[fd00::1]:8090"},
		{"loopback unchanged", "127.0.0.1", 8090, "127.0.0.1:8090"},
		{"port 0 falls back to the default port", "", 0, ":8080"},
		{"port 0 with a host keeps the host", "::", 0, "[::]:8080"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, bindAddr(c.host, c.port))
		})
	}
}
