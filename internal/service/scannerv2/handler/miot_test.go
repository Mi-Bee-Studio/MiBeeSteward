// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. You can use, copy, modify, and
// redistribute it under those terms; see LICENSE for the full text. A
// commercial license is available for use cases the AGPLv3 does not
// accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"testing"

	"github.com/stretchr/testify/require"

	"mibee-steward/internal/service/scannerv2"
)

// The orchestrator's HTTP-Server evidence fold runs before EnrichDevice and
// fills inferred_brand with the web-server software fronting a Mijia device's
// UI (field-found: "nginx" on a xiaomi-gateway-hub1). The ecosystem brand from
// the hostname fingerprint must override software names, but NOT a genuine
// protocol/OUI-derived vendor brand.
func TestMiotHandlerBrandOverridesWebServerName(t *testing.T) {
	h := MiotHandler{}

	// Case 1 (the field bug): nginx already set by the HTTP fold → overridden.
	svc := scannerv2.ServiceContext{
		Identity: scannerv2.ServiceIdentity{Service: "miot", Metadata: map[string]string{
			"inferred_brand": "Xiaomi",
			"ecosystem":      "Xiaomi Mijia",
			"appliance":      "gateway",
		}},
		Device: scannerv2.DeviceRef{Fields: map[string]string{"inferred_brand": "nginx"}},
	}
	h.EnrichDevice(svc, nil)
	require.Equal(t, "Xiaomi", svc.Device.Fields["inferred_brand"])
	require.Equal(t, "gateway · Xiaomi Mijia", svc.Device.Fields["inferred_description"])

	// Case 2: empty slot → filled (brand AND model, the model token comes from
	// the hostname rule's regex_capture).
	svc = scannerv2.ServiceContext{
		Identity: scannerv2.ServiceIdentity{Service: "miot", Metadata: map[string]string{
			"inferred_brand": "Viomi",
			"inferred_model": "e13",
		}},
		Device: scannerv2.DeviceRef{Fields: map[string]string{}},
	}
	h.EnrichDevice(svc, nil)
	require.Equal(t, "Viomi", svc.Device.Fields["inferred_brand"])
	require.Equal(t, "e13", svc.Device.Fields["inferred_model"])

	// Case 3: a genuine protocol/OUI-derived vendor brand wins the tie (and an
	// existing model is never clobbered by a hostname guess).
	svc = scannerv2.ServiceContext{
		Identity: scannerv2.ServiceIdentity{Service: "miot", Metadata: map[string]string{
			"inferred_brand": "Xiaomi",
			"inferred_model": "c16",
		}},
		Device: scannerv2.DeviceRef{Fields: map[string]string{
			"inferred_brand": "Hikvision",
			"inferred_model": "DS-2CD2143G2",
		}},
	}
	h.EnrichDevice(svc, nil)
	require.Equal(t, "Hikvision", svc.Device.Fields["inferred_brand"])
	require.Equal(t, "DS-2CD2143G2", svc.Device.Fields["inferred_model"])
}
