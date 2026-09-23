// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/config"
)

// The Start/Stop lifecycle races these tests pin were field-observed as a
// full-suite 15-minute hang in internal/api/routes: NewRouter launches
// `go heartbeatSvc.Start(...)`, and TestScannerIntegration issues Stop()
// immediately, if the delayed Start lands after Close already read a nil
// cancel, the old code waited on <-done forever while the late-launched
// flushLoop ran under a context nobody would cancel.

// Close on a never-started store must return instead of waiting on a flush
// loop that doesn't exist yet.
func TestHeartbeatStore_CloseBeforeStartReturns(t *testing.T) {
	store, err := OpenHeartbeatStore(filepath.Join(t.TempDir(), "heartbeat.db"))
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- store.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Close on a never-started store must not block")
	}
}

// A Start arriving after Close must not launch the flush loop, its cancel
// is unreachable, so the loop would leak and a subsequent Close would hang.
func TestHeartbeatStore_StartAfterCloseIsNoop(t *testing.T) {
	store, err := OpenHeartbeatStore(filepath.Join(t.TempDir(), "heartbeat.db"))
	require.NoError(t, err)
	require.NoError(t, store.Close())

	store.Start(context.Background())

	select {
	case <-store.done:
		t.Fatal("flushLoop must not have started after Close")
	default:
	}
	require.NoError(t, store.Close()) // still fine (idempotent-ish)
}

// Stop-before-Start on the service: Stop returns promptly, the late Start
// no-ops (no store flush loop, no sync loop), and the store is closed.
// mainDB is nil, Stop's final syncStatus finds an empty cache and writes
// nothing, which is exactly the never-started state under test.
func TestHeartbeatService_StopBeforeStartThenStartIsNoop(t *testing.T) {
	store, err := OpenHeartbeatStore(filepath.Join(t.TempDir(), "heartbeat.db"))
	require.NoError(t, err)
	svc := NewHeartbeatService(nil, store, &config.Config{})

	stopped := make(chan struct{})
	go func() {
		svc.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop before Start must not block")
	}

	started := make(chan struct{})
	go func() {
		svc.Start(context.Background())
		close(started)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("delayed Start after Stop must return (no loop)")
	}

	select {
	case <-store.done:
		t.Fatal("store flush loop must not have been started by the late Start")
	default:
	}
}
