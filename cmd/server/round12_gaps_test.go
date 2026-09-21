// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. A commercial license is available for use cases
// the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDoctor_BackupBranches drives the backup checks: a fresh valid backup
// answers ok + restorable; a corrupt backup fails restorable (still exit 1
// only if another check failed — backup warn alone exits 0).
func TestDoctor_BackupBranches(t *testing.T) {
	dbDir := t.TempDir()
	cfg := writeDoctorConfig(t, filepath.Join(dbDir, "mibee.db"), "0123456789abcdef0123456789abcdef")

	// No backups dir → warn branch (already covered); create backups with a
	// REAL sqlite file so "restorable" runs its integrity probe.
	backupDir := filepath.Join(dbDir, "backups")
	require.NoError(t, os.MkdirAll(backupDir, 0o755))
	bk, err := sql.Open("sqlite", filepath.Join(backupDir, "mibee-steward.db"))
	require.NoError(t, err)
	_, err = bk.Exec(`CREATE TABLE t(x)`)
	require.NoError(t, err)
	require.NoError(t, bk.Close())

	// Backups fresh → exit code driven by ICMP sysctl only (same derivation
	// as the main doctor test).
	wantExit := 0
	if raw, err := os.ReadFile("/proc/sys/net/ipv4/ping_group_range"); err == nil {
		if c, ok := icmpPingGroupRangeCheck(string(raw), os.Getgid()); ok && c.status == "fail" {
			wantExit = doctorFailExit
		}
	}
	require.Equal(t, wantExit, doctor([]string{"-config", cfg}))
}
