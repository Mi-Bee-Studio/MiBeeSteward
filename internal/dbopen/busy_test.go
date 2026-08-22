// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package dbopen

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeDBTX struct {
	execErrors []error // consumed one per ExecContext call, nil-terminated
	execCalls  int
}

func (f *fakeDBTX) ExecContext(_ context.Context, _ string, _ ...interface{}) (sql.Result, error) {
	i := f.execCalls
	f.execCalls++
	if i < len(f.execErrors) && f.execErrors[i] != nil {
		return nil, f.execErrors[i]
	}
	return fakeResult{}, nil
}
func (f *fakeDBTX) PrepareContext(context.Context, string) (*sql.Stmt, error) { return nil, nil }
func (f *fakeDBTX) QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error) {
	return nil, nil
}
func (f *fakeDBTX) QueryRowContext(context.Context, string, ...interface{}) *sql.Row { return nil }

type fakeResult struct{}

func (fakeResult) LastInsertId() (int64, error) { return 0, nil }
func (fakeResult) RowsAffected() (int64, error) { return 1, nil }

var errBusy = errors.New("(5) (2006) SQLITE_BUSY: database is locked")

func fastRetry(b *BusyRetry) *BusyRetry {
	b.maxRetries = 3
	b.baseDelay = time.Millisecond
	return b
}

func TestBusyRetry_RetriesUntilSuccess(t *testing.T) {
	fake := &fakeDBTX{execErrors: []error{errBusy, errBusy, nil}}
	br := fastRetry(WrapBusyRetry(fake, "test"))
	_, err := br.ExecContext(context.Background(), "INSERT INTO x VALUES (1)")
	require.NoError(t, err)
	require.Equal(t, 3, fake.execCalls, "two BUSY then success = three calls")
}

func TestBusyRetry_ExhaustsAndReturnsLastError(t *testing.T) {
	fake := &fakeDBTX{execErrors: []error{errBusy, errBusy, errBusy, errBusy}}
	br := fastRetry(WrapBusyRetry(fake, "test"))
	_, err := br.ExecContext(context.Background(), "INSERT INTO x VALUES (1)")
	require.ErrorIs(t, err, errBusy)
	require.Equal(t, 4, fake.execCalls, "initial + 3 retries")
}

func TestBusyRetry_NonBusyPassesThrough(t *testing.T) {
	foreign := errors.New("no such table: x")
	fake := &fakeDBTX{execErrors: []error{foreign}}
	br := fastRetry(WrapBusyRetry(fake, "test"))
	_, err := br.ExecContext(context.Background(), "SELECT 1")
	require.ErrorIs(t, err, foreign)
	require.Equal(t, 1, fake.execCalls, "non-BUSY errors never retry")
}

func TestBusyRetry_TableLockedVariantsDetected(t *testing.T) {
	tableLocked := errors.New("database table is locked")
	fake := &fakeDBTX{execErrors: []error{tableLocked, nil}}
	br := fastRetry(WrapBusyRetry(fake, "test"))
	_, err := br.ExecContext(context.Background(), "INSERT INTO x VALUES (1)")
	require.NoError(t, err)
	require.Equal(t, 2, fake.execCalls)
}

func TestWrapBusyRetry_NoDoubleWrap(t *testing.T) {
	fake := &fakeDBTX{}
	first := WrapBusyRetry(fake, "a")
	second := WrapBusyRetry(first, "b")
	require.Same(t, first, second, "re-wrapping must return the existing wrapper (label 'a' wins)")
}
