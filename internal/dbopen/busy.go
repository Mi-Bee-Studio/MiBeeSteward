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
	"log/slog"
	"strings"
	"time"

	"mibee-steward/internal/metrics"
)

// DBTX mirrors db.DBTX (the four context-aware methods every sql wrapper
// needs). Declared locally so dbopen stays importable by internal/db's
// consumers without a cycle.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// BusyRetry is a db.DBTX wrapper that retries SQLITE_BUSY failures with
// bounded backoff and counts every occurrence into
// mibee_sqlite_busy_total{path} (#267 — single-writer governance: SQLite
// allows ONE writer; the scanner's result persistence, the heartbeat verdict
// flush, probe results and audit writes compete, and a write that outlived
// busy_timeout (5s via the DSN) used to fail — audit writes even dropped
// silently, one failed attempt and gone).
//
// It implements db.DBTX plus BeginTx (when the wrapped handle is a *sql.DB),
// so it drops into subsystems that previously took the raw pool. Explicit
// transactions are pass-through by design: a BUSY inside a tx must surface to
// the caller, which owns the rollback semantics.
type BusyRetry struct {
	inner  DBTX
	pool   *sql.DB // non-nil iff inner is *sql.DB (BeginTx/Close/Ping passthrough)
	path   string
	logger *slog.Logger

	maxRetries int
	baseDelay  time.Duration
}

// WrapBusyRetry wraps one call path's DB handle. path becomes the
// mibee_sqlite_busy_total{path} label — use the subsystem name ("scanner",
// "heartbeat", "audit", …) so contention pins to its source.
func WrapBusyRetry(dbtx DBTX, path string) *BusyRetry {
	if br, ok := dbtx.(*BusyRetry); ok {
		return br // never double-wrap
	}
	br := &BusyRetry{
		inner:      dbtx,
		path:       path,
		logger:     slog.Default(),
		maxRetries: 5,
		baseDelay:  50 * time.Millisecond,
	}
	if db, ok := dbtx.(*sql.DB); ok {
		br.pool = db
	}
	return br
}

// ExecContext retries on SQLITE_BUSY.
func (b *BusyRetry) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	var res sql.Result
	err := b.retry(ctx, "exec", func() error {
		var e error
		res, e = b.inner.ExecContext(ctx, query, args...)
		return e
	})
	return res, err
}

// QueryContext retries on SQLITE_BUSY.
func (b *BusyRetry) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	var rows *sql.Rows
	err := b.retry(ctx, "query", func() error {
		var e error
		rows, e = b.inner.QueryContext(ctx, query, args...)
		return e
	})
	return rows, err
}

// QueryRowContext is pass-through: *sql.Row defers its error to Scan, so a
// BUSY can't be detected at call time to retry against. WAL readers block
// only behind the single writer's commit window, which busy_timeout absorbs.
func (b *BusyRetry) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	return b.inner.QueryRowContext(ctx, query, args...)
}

// PrepareContext retries on SQLITE_BUSY.
func (b *BusyRetry) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	var stmt *sql.Stmt
	err := b.retry(ctx, "prepare", func() error {
		var e error
		stmt, e = b.inner.PrepareContext(ctx, query)
		return e
	})
	return stmt, err
}

// BeginTx passes through to the wrapped pool (explicit transactions own
// their BUSY handling — see the type comment).
func (b *BusyRetry) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	if b.pool == nil {
		return nil, errors.New("dbopen: BusyRetry BeginTx requires a *sql.DB inner handle")
	}
	return b.pool.BeginTx(ctx, opts)
}

// Close passes through to the wrapped pool.
func (b *BusyRetry) Close() error {
	if b.pool == nil {
		return errors.New("dbopen: BusyRetry Close requires a *sql.DB inner handle")
	}
	return b.pool.Close()
}

// Pool returns the wrapped *sql.DB (nil when the inner handle wasn't a
// pool). For callers that need concrete-handle methods (Close, SetMaxOpenConns)
// alongside the wrapped write path.
func (b *BusyRetry) Pool() *sql.DB { return b.pool }

// retry runs op until it succeeds, is not BUSY, or the budget is exhausted.
// Every BUSY increments mibee_sqlite_busy_total{path} — including the
// exhausted case, so sustained contention stays visible even when the retry
// ultimately fails.
func (b *BusyRetry) retry(ctx context.Context, op string, fn func() error) error {
	delay := b.baseDelay
	for attempt := 0; ; attempt++ {
		err := fn()
		if err == nil || !isBusy(err) {
			return err
		}
		metrics.MibeeSqliteBusyTotal.WithLabelValues(b.path).Inc()
		if attempt >= b.maxRetries {
			b.logger.Error("sqlite BUSY retries exhausted",
				"path", b.path, "op", op, "attempts", attempt+1, "error", err)
			return err
		}
		b.logger.Warn("sqlite BUSY, retrying write",
			"path", b.path, "op", op, "attempt", attempt+1,
			"delay", delay.String(), "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// isBusy reports whether err is an SQLITE_BUSY-family failure. String
// matching rather than modernc's typed error: the error text ("(5) (2006)
// SQLITE_BUSY: database is locked", "database table is locked" for
// deferred-tx upgrade deadlocks) is stable across the driver's versions and
// this stays driver-agnostic for tests.
func isBusy(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_BUSY") ||
		strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "database table is locked")
}
