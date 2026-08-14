// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

package scopeql

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/domain"
)

func TestNetworkPredicate(t *testing.T) {
	cases := []struct {
		name     string
		scope    domain.Scope
		alias    string
		wantPred string
		wantArgs []any
	}{
		{
			name:     "global is no-op 1=1",
			scope:    domain.Scope{Global: true},
			wantPred: "1=1",
			wantArgs: []any(nil),
		},
		{
			name:     "restricted empty matches nothing",
			scope:    domain.Scope{Global: false, NetworkIDs: nil},
			wantPred: "0",
			wantArgs: []any(nil),
		},
		{
			name:     "restricted single network bare column",
			scope:    domain.Scope{Global: false, NetworkIDs: []int64{7}},
			wantPred: "network_id IN (?)",
			wantArgs: []any{int64(7)},
		},
		{
			name:     "restricted multiple networks with alias",
			scope:    domain.Scope{Global: false, NetworkIDs: []int64{1, 2, 3}},
			alias:    "d",
			wantPred: "d.network_id IN (?,?,?)",
			wantArgs: []any{int64(1), int64(2), int64(3)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pred, args := NetworkPredicate(tc.scope, tc.alias)
			require.Equal(t, tc.wantPred, pred)
			require.Equal(t, tc.wantArgs, args)
		})
	}
}
