// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate. See
// LICENSE-COMMERCIAL.md.

package handler

import "testing"

// Coverage-headroom pin (#697) for the CollectedData Service() tags — these
// strings are the pipeline's data→handler routing keys, so renaming one by
// accident should fail here before it fails a scan.
func TestCollectedDataServiceTags(t *testing.T) {
	for _, tc := range []struct {
		data interface{ Service() string }
		want string
	}{{HTTPData{}, "http"}, {PrometheusData{}, "prometheus"}, {NodeExporterData{}, "node_exporter"}, {PlainData{S: "ssh"}, "ssh"}} {
		if got := tc.data.Service(); got != tc.want {
			t.Errorf("Service() = %q, want %q", got, tc.want)
		}
	}
}
