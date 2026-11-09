// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package config

import (
	"os"
	"testing"
)

// Announce is ON without any yaml block: pre-#729 configs (the #727 upgrade
// path — "existing config kept as-is" means the block never appears) must
// still get announcing defaults from the seed map, not a zeroed struct that
// silently disables the feature.
func TestAnnounceDefaultsOnWithoutYAMLBlock(t *testing.T) {
	cfg, err := Load(writeConfigYAML(t))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Announce.Enabled {
		t.Fatalf("announce.enabled = false, want seeded default true")
	}
	if !cfg.Announce.MDNS || !cfg.Announce.UDP {
		t.Fatalf("announce sub-switches mdns=%v udp=%v, want both true", cfg.Announce.MDNS, cfg.Announce.UDP)
	}
	if cfg.Announce.UDPPort != 49091 {
		t.Fatalf("announce.udp_port = %d, want 49091", cfg.Announce.UDPPort)
	}
}

// Explicit keys win over the seed, and a partial block keeps seed values for
// the keys it doesn't mention (the koanf per-key override guarantee).
func TestAnnounceExplicitKeysOverrideSeed(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "cfg-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.WriteString(`server: {port: 8080, host: "0.0.0.0"}
auth:
  jwt_secret: "this-is-definitely-32-chars-long!!"
  initial_admin_password: "from-yaml"
announce:
  enabled: false
  udp_port: 49099
`); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	cfg, err := Load(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Announce.Enabled {
		t.Fatalf("announce.enabled = true, want explicit false to win")
	}
	if cfg.Announce.UDPPort != 49099 {
		t.Fatalf("announce.udp_port = %d, want explicit 49099", cfg.Announce.UDPPort)
	}
	// Unmentioned keys keep the seed even inside a partial block.
	if !cfg.Announce.MDNS {
		t.Fatalf("announce.mdns = false, want seed true (partial block must not zero unmentioned keys)")
	}
}
