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

	"mibee-steward/internal/service/scannerv2"
)

// mdnsSsdpEnrich folds a self-announcement identity (mdns-ssdp.yaml rules,
// service "mdns"/"ssdp") into the device record. The device bridge documents
// mDNS service types as protocol-grade evidence, so the type set here is NOT
// flagged heuristic (no ? badge) — but preserveExisting keeps stronger
// in-protocol evidence (SNMP sysObjectID, an actual ONVIF exchange) in charge
// when both ran. Heartbeat: none — announcements carry no probeable port
// (Port is the 5353/1900 listener, not the service), and the bridge already
// seeds ICMP for every discovered host.
func mdnsSsdpEnrich(svc scannerv2.ServiceContext) {
	md := svc.Identity.Metadata
	if t, ok := md["inferred_type"]; ok && t != "" {
		preserveExisting(svc, "inferred_type", t)
	}
	if b, ok := md["inferred_brand"]; ok && b != "" {
		preserveExisting(svc, "inferred_brand", b)
	}
	if d, ok := md["inferred_description"]; ok && d != "" {
		preserveExisting(svc, "inferred_description", d)
	}
	if m, ok := md["model"]; ok && m != "" {
		preserveExisting(svc, "inferred_model", m)
	}
}

// MdnsHandler hosts the "mdns" identity from the active mDNS probe's
// Kind="mdns" evidence (services list + TXT records).
type MdnsHandler struct{}

func (MdnsHandler) Service() string { return "mdns" }

func (MdnsHandler) GenerateHeartbeat(_ scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return nil
}

func (MdnsHandler) Collect(_ context.Context, _ scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return nil, nil, nil
}

func (MdnsHandler) EnrichDevice(svc scannerv2.ServiceContext, _ scannerv2.CollectedData) {
	mdnsSsdpEnrich(svc)
}

// SsdpHandler hosts the "ssdp" identity from the SSDP M-SEARCH probe's
// Kind="ssdp" evidence (SERVER/USN/LOCATION self-declarations).
type SsdpHandler struct{}

func (SsdpHandler) Service() string { return "ssdp" }

func (SsdpHandler) GenerateHeartbeat(_ scannerv2.ServiceContext) *scannerv2.HeartbeatSpec {
	return nil
}

func (SsdpHandler) Collect(_ context.Context, _ scannerv2.ServiceContext) (scannerv2.CollectedData, []scannerv2.Trigger, error) {
	return nil, nil, nil
}

func (SsdpHandler) EnrichDevice(svc scannerv2.ServiceContext, _ scannerv2.CollectedData) {
	mdnsSsdpEnrich(svc)
}
