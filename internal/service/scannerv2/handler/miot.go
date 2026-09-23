// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL license does not accommodate; see LICENSE-COMMERCIAL.md.

package handler

import (
	"context"
	"strings"

	"mibee-steward/internal/service/scannerv2"
)

// MiotHandler is the host-level identity for Xiaomi Mijia ecosystem devices
// (service "miot", emitted by the iot-identity.yaml hostname rules). On real
// Mijia fleets the DHCP/rDNS hostname is the ONLY identity channel, 0/12
// responses to mDNS, miIO hello and TCP ports in the #365 field PoC, so the
// identity carries brand/appliance metadata only. The device TYPE stays a
// hostname heuristic (the ? badge) via device-types/device_types.yaml; this
// handler never touches inferred_type.
//
// Heartbeat: none. The identity has no port (Port=0), and the device bridge
// already seeds an ICMP heartbeat for every discovered host.
type MiotHandler struct{}

func (MiotHandler) Service() string { return "miot" }

func (MiotHandler) GenerateHeartbeat(_ scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return nil
}

func (MiotHandler) Collect(_ context.Context, _ scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return nil, nil, nil
}

func (MiotHandler) EnrichDevice(svc scannerv2.ServiceContext, _ scannerv2.CollectedData) {
	// Brand: fill the empty slot only, a protocol-derived brand (SNMP/TLS,
	// set by other handlers) outranks a spoofable hostname; the OUI fold runs
	// before handlers, so a NIC-silicon vendor may already sit there and wins
	// the tie (both are heuristic-grade for these devices).
	if b, ok := svc.Identity.Metadata["inferred_brand"]; ok && b != "" {
		preserveExisting(svc, "inferred_brand", b)
	}

	// Description: "<appliance> · <ecosystem>" when the rules extracted an
	// appliance, else just the ecosystem.
	var parts []string
	if ap, ok := svc.Identity.Metadata["appliance"]; ok && ap != "" {
		parts = append(parts, ap)
	}
	if eco, ok := svc.Identity.Metadata["ecosystem"]; ok && eco != "" {
		parts = append(parts, eco)
	}
	if len(parts) > 0 {
		preserveExisting(svc, "inferred_description", strings.Join(parts, " · "))
	}
}
