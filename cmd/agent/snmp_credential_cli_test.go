// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSNMPCredentialSubcommand_ListWithoutMasterKey pins the os.Exit-free CLI
// shell: `list` on a vault-less config prints the disabled warning but still
// completes (every OTHER action exits, only list is testable in-process).
func TestSNMPCredentialSubcommand_ListWithoutMasterKey(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "agent.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("server:\n  port: 0\nauth:\n  jwt_secret: 0123456789abcdef0123456789abcdef\n"), 0o600))

	// Runs to completion (no os.Exit on the list path without a master key).
	snmpCredentialSubcommand([]string{"-config", cfgPath, "-action", "list"})

	// The vault DB was created beside the config (openAgentDB applies the
	// mini-schema on first use).
	_, err := os.Stat(filepath.Join(filepath.Dir(cfgPath), "agent.db"))
	require.NoError(t, err)
}
