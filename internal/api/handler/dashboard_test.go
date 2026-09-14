// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidateWidgetConfig is a table test over the pure validation shared by
// the dashboard Create/Update handlers. PromQL widgets keep the legacy rules
// (chart types only, name required); builtin widgets must carry a whitelisted
// template key whose declared type matches what the frontend renders.
func TestValidateWidgetConfig(t *testing.T) {
	tests := []struct {
		name       string
		widgetName string
		widgetType string
		dataSource string
		query      string
		wantDS     string // expected defaulted data_source; "" when an error is expected
		wantErr    string // substring of the expected error, "" when valid
	}{
		// Legacy prometheus shapes — must keep working unchanged.
		{"prometheus gauge", "CPU", "gauge", "prometheus", "up", "prometheus", ""},
		{"prometheus default ds", "CPU", "line", "", "rate(up[5m])", "prometheus", ""},
		{"victoriametrics alias", "CPU", "gauge", "victoriametrics", "up", "victoriametrics", ""},
		{"missing name", "", "gauge", "prometheus", "up", "", "name is required"},
		{"bad type", "CPU", "table", "prometheus", "up", "", "type must be one of"},
		{"list rejected for prometheus", "X", "list", "prometheus", "up", "", "type must be one of"},
		{"empty query rejected", "CPU", "gauge", "prometheus", "", "", "query is required"},

		// Builtin presets.
		{"builtin status pie", "Status", "pie", "builtin", "builtin:device_status", "builtin", ""},
		{"builtin changes list", "Changes", "list", "builtin", "builtin:recent_changes", "builtin", ""},
		{"builtin unknown key", "X", "list", "builtin", "builtin:nope", "", "unknown builtin widget template"},
		{"builtin type mismatch", "X", "pie", "builtin", "builtin:recent_changes", "", "must use type list"},
		{"builtin bare key rejected", "X", "list", "builtin", "recent_changes", "", "unknown builtin widget template"},

		// Unknown data_source.
		{"bad data_source", "X", "gauge", "influxdb", "up", "", "data_source must be one of"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds, err := validateWidgetConfig(tt.widgetName, tt.widgetType, tt.dataSource, tt.query)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantDS, ds)
		})
	}
}

// TestBuiltinWidgetTemplatesUniqueTypes guards the template table itself:
// every key must start with the "builtin:" prefix so the whitelist can't be
// confused with raw PromQL, and the set must cover at least one preset of
// every rendering kind the frontend gallery offers.
func TestBuiltinWidgetTemplatesUniqueTypes(t *testing.T) {
	kinds := map[string]bool{"pie": false, "bar": false, "gauge": false, "list": false}
	for key, typ := range builtinWidgetTemplates {
		require.True(t, strings.HasPrefix(key, "builtin:"),
			"template key %q must carry the builtin: prefix", key)
		require.Contains(t, kinds, typ, "template %q has unknown type %q", key, typ)
		kinds[typ] = true
	}
	for kind, seen := range kinds {
		require.True(t, seen, "no builtin template renders as %q — the gallery would offer a dead preset", kind)
	}
}
