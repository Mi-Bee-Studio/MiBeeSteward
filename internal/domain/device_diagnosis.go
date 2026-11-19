// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package domain

import "time"

// Network-anomaly diagnosis (#761): a read-model that joins the
// address-observation history (device_sightings), the per-IP liveness facts
// (scan_snapshots), the multi-homed presence layer (device_network_presence),
// and the change stream (change_log) into a classified verdict with an
// evidence chain. Field-verified against the 2026-11-19 incident: one ghost
// box split into four rows, with sightings recorded at ~30 addresses none of
// which answered on the wire — a stale-ARP artifact, not DHCP churn.

// DiagnosisFindingCode classifies one observed anomaly pattern. Values are
// stable API contract (frontend i18n keys are derived from them).
type DiagnosisFindingCode string

const (
	// DiagnosisStaleARPArtifact: many addresses observed for one MAC, none of
	// which carry a live scan hit (missing snapshot or miss_count > 0). The
	// sightings come from stale ARP-cache entries read by the scanner — an
	// address-drift illusion, not a device that keeps changing its IP.
	DiagnosisStaleARPArtifact DiagnosisFindingCode = "stale_arp_scan_artifact"
	// DiagnosisMultihomedAlias: the same asset is (or was) actively present in
	// more than one network — dual-homed bridging or roaming, not drift.
	DiagnosisMultihomedAlias DiagnosisFindingCode = "multihomed_alias"
	// DiagnosisLocallyAdministeredMAC: the identity MAC has the U/L bit set —
	// a virtual/soft MAC (VM, container, VPN). MAC-based IP binding will not
	// stick for interfaces like this; it is a neutral fact, not a
	// randomization verdict.
	DiagnosisLocallyAdministeredMAC DiagnosisFindingCode = "locally_administered_mac"
	// DiagnosisIPSlotTakeover: the change stream recorded a MAC replacement at
	// an unchanged address — another identity took over the slot (board swap,
	// fresh DHCP identity, or ARP spoofing).
	DiagnosisIPSlotTakeover DiagnosisFindingCode = "ip_slot_takeover"
	// DiagnosisHostnameSplit: other device rows announce the same hostname
	// under different MACs — one physical box split across identity rows.
	DiagnosisHostnameSplit DiagnosisFindingCode = "hostname_identity_split"
)

// DiagnosisSeverity ranks a finding. Only critical/warning make the overall
// verdict an anomaly; info-level findings are context, per the "alert on
// impact, not on change" principle.
type DiagnosisSeverity string

const (
	DiagnosisSeverityInfo     DiagnosisSeverity = "info"
	DiagnosisSeverityWarning  DiagnosisSeverity = "warning"
	DiagnosisSeverityCritical DiagnosisSeverity = "critical"
)

// DiagnosisEvidence is one machine-checkable fact backing a finding.
type DiagnosisEvidence struct {
	// Kind names the fact source: sighting | snapshot | change | attribute |
	// presence | sibling.
	Kind string `json:"kind"`
	// Detail is a stable English one-line rendering of the fact (frontend
	// renders its own localized headline; the detail is the raw fact).
	Detail string `json:"detail"`
	// At is the fact's timestamp when one exists.
	At *time.Time `json:"at,omitempty"`
}

// DiagnosisFinding is one classified pattern with its evidence chain.
type DiagnosisFinding struct {
	Code     DiagnosisFindingCode `json:"code"`
	Severity DiagnosisSeverity    `json:"severity"`
	// Summary is a stable English one-sentence verdict for this finding.
	Summary  string              `json:"summary"`
	Evidence []DiagnosisEvidence `json:"evidence"`
}

// DiagnosisAddress aggregates every sighting of one address into a single
// liveness-annotated row for the timeline.
type DiagnosisAddress struct {
	IPAddress string `json:"ip_address"`
	// MACs are the distinct identities the sightings carried for this
	// address (usually one; several hints at alias churn).
	MACs []string `json:"macs"`
	// Alive: the address carries a fresh scan hit (snapshot miss_count == 0).
	Alive bool `json:"alive"`
	// MissingScans: consecutive scans the address was absent from (0 when
	// alive; -1 when the address has no snapshot at all — never seen alive).
	MissingScans int `json:"missing_scans"`
	// FlapCount: liveness transitions recorded for the address.
	FlapCount int       `json:"flap_count"`
	SeeCount  int64     `json:"see_count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// Sources / Vantages enumerate where the observations came from.
	Sources  []string `json:"sources"`
	Vantages []string `json:"vantages"`
	// Current marks the address the device row currently points at.
	Current bool `json:"current"`
}

// DiagnosisSibling is another device row sharing this device's hostname —
// the identity-split signal.
type DiagnosisSibling struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Status    string     `json:"status"`
	IPAddress string     `json:"ip_address"`
	MAC       string     `json:"mac_address,omitempty"`
	Hostname  string     `json:"hostname,omitempty"`
	NetworkID int64      `json:"network_id"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
}

// DeviceNetworkDiagnosis is the full per-device verdict.
type DeviceNetworkDiagnosis struct {
	DeviceID     int64  `json:"device_id"`
	DeviceName   string `json:"device_name"`
	DeviceMAC    string `json:"device_mac,omitempty"`
	DeviceIP     string `json:"device_ip,omitempty"`
	DeviceStatus string `json:"device_status"`
	// Status of the verdict itself: "anomaly" (critical/warning finding),
	// "watch" (info-level only), "healthy" (nothing observed).
	Status string `json:"status"`
	// Classification is the highest-severity finding's code ("" when none).
	Classification DiagnosisFindingCode `json:"classification"`
	// Confidence: "high" when the verdict rests on liveness facts, "medium"
	// when only sighting-shape evidence backs it, "" when healthy.
	Confidence  string             `json:"confidence,omitempty"`
	Summary     string             `json:"summary"`
	Findings    []DiagnosisFinding `json:"findings"`
	Addresses   []DiagnosisAddress `json:"addresses"`
	Siblings    []DiagnosisSibling `json:"siblings"`
	GeneratedAt time.Time          `json:"generated_at"`
}
