// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package domain

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnmarshalScanAttributesPtr(t *testing.T) {
	// NULL column → zero attributes, no error.
	attrs, err := UnmarshalScanAttributesPtr(sql.NullString{})
	require.NoError(t, err)
	require.Equal(t, ScanAttributes{}, attrs)

	// Valid JSON → parsed fields.
	attrs, err = UnmarshalScanAttributesPtr(sql.NullString{String: `{"vendor":"acme","mac":"AA:BB"}`, Valid: true})
	require.NoError(t, err)
	require.Equal(t, "acme", attrs.Vendor)

	// Invalid JSON → error (the caller decides between failing and treating
	// the row as unparseable).
	_, err = UnmarshalScanAttributesPtr(sql.NullString{String: `{nope`, Valid: true})
	require.Error(t, err)
}
