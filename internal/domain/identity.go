// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not accommodate;
// see LICENSE-COMMERCIAL.md.

package domain

import "time"

// IdentityConfidence ranks a candidate match. It is deliberately explainable:
// high/medium/low is derived from the signals below, never a black-box score.
type IdentityConfidence string

const (
	IdentityConfidenceHigh   IdentityConfidence = "high"
	IdentityConfidenceMedium IdentityConfidence = "medium"
	IdentityConfidenceLow    IdentityConfidence = "low"
)

// IdentitySignal names a machine-checkable reason two rows may represent the
// same physical asset. IP and OUI are intentionally absent: neither proves
// identity on its own.
type IdentitySignal string

const (
	IdentitySignalHostname    IdentitySignal = "hostname"
	IdentitySignalMACAlias    IdentitySignal = "mac_alias"
	IdentitySignalSerial      IdentitySignal = "serial"
	IdentitySignalCertificate IdentitySignal = "certificate"
)

// IdentityEvidence is one fact backing a candidate. ObservedAt is the source
// row's freshness marker when one exists.
type IdentityEvidence struct {
	Signal     IdentitySignal `json:"signal"`
	Source     string         `json:"source"`
	Detail     string         `json:"detail"`
	Vantage    string         `json:"vantage,omitempty"`
	ObservedAt *time.Time     `json:"observed_at,omitempty"`
}

// IdentityDevice is the read-only identity projection used by both the device
// list badges and the review page/detail panel.
type IdentityDevice struct {
	ID               int64      `json:"id"`
	UUID             string     `json:"device_uuid"`
	Name             string     `json:"name"`
	Type             string     `json:"type"`
	Brand            string     `json:"brand"`
	Model            string     `json:"model"`
	IPAddress        string     `json:"ip_address"`
	MACAddress       string     `json:"mac_address"`
	Hostname         string     `json:"hostname,omitempty"`
	SerialNumber     string     `json:"serial_number,omitempty"`
	NetworkID        *int64     `json:"network_id"`
	Status           string     `json:"status"`
	ArchivedAt       *time.Time `json:"archived_at,omitempty"`
	FirstSeen        *time.Time `json:"first_seen,omitempty"`
	LastSeen         *time.Time `json:"last_seen,omitempty"`
	Aliases          []string   `json:"mac_aliases"`
	CertFingerprints []string   `json:"certificate_fingerprints,omitempty"`
	MultiHomed       bool       `json:"multi_homed"`
	Stale            bool       `json:"stale"`
	EvidenceCoverage float64    `json:"evidence_coverage"`
}

// IdentityCandidate is a review suggestion, not an automatic merge decision.
type IdentityCandidate struct {
	ID              string             `json:"id"`
	Kind            string             `json:"kind"`
	Confidence      IdentityConfidence `json:"confidence"`
	Score           int                `json:"score"`
	Signals         []IdentitySignal   `json:"signals"`
	Evidence        []IdentityEvidence `json:"evidence"`
	CounterEvidence []string           `json:"counter_evidence"`
	TemporalOverlap bool               `json:"temporal_overlap"`
	DeviceA         IdentityDevice     `json:"device_a"`
	DeviceB         IdentityDevice     `json:"device_b"`
}

// IdentitySummary is computed over the scoped active inventory before
// pagination. Rates are 0..1.
type IdentitySummary struct {
	TotalDevices     int64   `json:"total_devices"`
	CandidateCount   int64   `json:"candidate_count"`
	HighCount        int64   `json:"high_count"`
	MediumCount      int64   `json:"medium_count"`
	LowCount         int64   `json:"low_count"`
	UnknownRate      float64 `json:"unknown_rate"`
	StaleRate        float64 `json:"stale_rate"`
	EvidenceCoverage float64 `json:"evidence_coverage"`
}

// IdentityCandidateList is the paginated review response.
type IdentityCandidateList struct {
	Candidates []IdentityCandidate `json:"candidates"`
	Summary    IdentitySummary     `json:"summary"`
	Total      int                 `json:"total"`
	Limit      int                 `json:"limit"`
	Offset     int                 `json:"offset"`
}

// DeviceIdentity is the per-device projection plus its review candidates.
type DeviceIdentity struct {
	Device     IdentityDevice      `json:"device"`
	Candidates []IdentityCandidate `json:"candidates"`
}
