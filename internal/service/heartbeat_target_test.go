// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestResolveLiveTarget covers the DHCP-roam fix: a heartbeat config's frozen
// target must be rewritten to the device's CURRENT ip_address so a roamed
// device is probed at its live address on the next tick. Each method's target
// shape (bare host / host:port / scheme URL) is exercised.
func TestResolveLiveTarget(t *testing.T) {
	const frozen = "192.168.63.187"
	const live = "192.168.63.60"

	tests := []struct {
		name   string
		frozen string
		live   string
		want   string
	}{
		{"icmp bare host", frozen, live, live},
		{"snmp bare host", frozen, live, live},
		{"tcp host:port", "192.168.63.187:80", live, "192.168.63.60:80"},
		{"http scheme url", "http://192.168.63.187:80/health", live, "http://192.168.63.60:80/health"},
		{"https scheme url default port", "https://192.168.63.187/", live, "https://192.168.63.60/"},
		{"onvif scheme url", "http://192.168.63.187:8080/onvif/device_service", live, "http://192.168.63.60:8080/onvif/device_service"},
		{"no change when live empty (frozen kept)", frozen, "", frozen},
		{"no change when both empty", "", "", ""},
		{"url path + query preserved", "http://192.168.63.187:8080/path?q=1", live, "http://192.168.63.60:8080/path?q=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveLiveTarget(tt.frozen, tt.live)
			assert.Equal(t, tt.want, got)
		})
	}
}
