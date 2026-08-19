// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package service

import (
	"context"
	"errors"
	"strconv"
	"time"

	"mibee-steward/internal/db"
)

// ScannerResultService is the write path for scan results (issue #240:
// BulkDeleteResults was the scanner_result handler's one grandfathered
// mutation). Everything else in that handler is a read passthrough.
type ScannerResultService struct {
	queries *db.Queries
}

// NewScannerResultService constructs a ScannerResultService.
func NewScannerResultService(queries *db.Queries) *ScannerResultService {
	return &ScannerResultService{queries: queries}
}

var (
	// ErrBeforeDateRequired / ErrBeforeDateInvalid / ErrBeforeDateNotPast map
	// to 400 with the historical message strings (kept verbatim — the
	// frontend surfaces them directly).
	ErrBeforeDateRequired = errors.New("before_date query parameter is required (ISO 8601 format)")
	ErrBeforeDateInvalid  = errors.New("invalid before_date format, use ISO 8601")
	ErrBeforeDateNotPast  = errors.New("before_date must be in the past")
)

// BulkDeleteBefore removes scan results older than the given instant.
// DeleteScanResultsOlderThan takes a SQLite `date(...)`-style day delta
// string, so the RFC3339 instant is converted to "days ago" here.
func (s *ScannerResultService) BulkDeleteBefore(ctx context.Context, before time.Time) (int64, error) {
	days := int(time.Since(before).Hours() / 24)
	if days <= 0 {
		return 0, ErrBeforeDateNotPast
	}
	daysStr := strconv.Itoa(days)
	return s.queries.DeleteScanResultsOlderThan(ctx, &daysStr)
}
