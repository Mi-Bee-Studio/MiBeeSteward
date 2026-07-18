// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package domain

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// ScanAttributes is the engine-written aggregation of everything a scan
// discovered about a device. It is serialized as JSON into the devices.
// scan_attributes column. The four generated columns
// (scan_vendor / scan_mac / scan_os / scan_hostname) are derived from the
// top-level Vendor / MAC / OS / Hostname fields via json_extract, so those
// field names and JSON keys are part of the query contract — rename with care.
//
// Ownership: ONLY the scanner engine (scannerv2 device bridge + store) writes
// this struct. User edits go to UserAttributes. The split keeps engine and
// user data from clobbering each other.
type ScanAttributes struct {
	// Identity / hardware
	Vendor   string `json:"vendor,omitempty"`   // OUI lookup or SNMP/HTTP-derived vendor
	MAC      string `json:"mac,omitempty"`      // normalized lowercase "aa:bb:cc:.."
	Hostname string `json:"hostname,omitempty"` // rDNS / mDNS / TLS CN / SNMP sysName

	// OS / firmware
	OS              string `json:"os,omitempty"`             // "Linux", "Windows", "iOS", …
	OSVersion       string `json:"os_version,omitempty"`     // parsed version string
	KernelVersion   string `json:"kernel_version,omitempty"` // node_exporter node_uname_info release
	FirmwareVersion string `json:"firmware_version,omitempty"`

	// Resources (node_exporter)
	CPUCount         int    `json:"cpu_count,omitempty"`
	CPUModel         string `json:"cpu_model,omitempty"`
	MemoryTotalBytes int64  `json:"memory_total_bytes,omitempty"`

	// Liveness / timing
	UptimeSeconds int64  `json:"uptime_seconds,omitempty"`
	TTL           int    `json:"ttl,omitempty"`
	LastScanRttMs int64  `json:"last_scan_rtt_ms,omitempty"`
	ScanSource    string `json:"scan_source,omitempty"`
	LastScannedAt string `json:"last_scanned_at,omitempty"` // RFC3339; empty when never scanned

	// Scanner classification summary
	InferredType        string `json:"inferred_type,omitempty"`
	InferredDescription string `json:"inferred_description,omitempty"`

	// Discovery surfaces (kept struct-shaped where stable, free-form otherwise)
	SNMP             *SNMPDiscovery  `json:"snmp,omitempty"`
	OpenPorts        []OpenPortEntry `json:"open_ports,omitempty"`
	DetectedServices []ServiceEntry  `json:"detected_services,omitempty"`
	Prometheus       *PrometheusInfo `json:"prometheus,omitempty"`

	// Free-form overflow for probe-specific output that doesn't fit a typed
	// field above (e.g. mDNS TXT records, SSDP location, TLS SAN list).
	// Keys are dotted namespaced by source ("mdns.model", "ssdp.server", …).
	Extras map[string]string `json:"extras,omitempty"`
}

// SNMPDiscovery holds the parsed result of an SNMP sysObject query.
type SNMPDiscovery struct {
	SysDescr    string `json:"sys_descr,omitempty"`
	SysObjectID string `json:"sys_object_id,omitempty"`
	SysName     string `json:"sys_name,omitempty"`
	SysLocation string `json:"sys_location,omitempty"`
	SysContact  string `json:"sys_contact,omitempty"`
	SysServices int    `json:"sys_services,omitempty"`
}

// OpenPortEntry is one element of ScanAttributes.OpenPorts. Shape must match
// the legacy open_ports JSON column so the frontend parser can read either.
type OpenPortEntry struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

// ServiceEntry mirrors the legacy detected_services element shape.
type ServiceEntry struct {
	Port     int    `json:"port"`
	Name     string `json:"name"`
	Protocol string `json:"protocol,omitempty"`
	Version  string `json:"version,omitempty"`
}

// PrometheusInfo aggregates prometheus_url / node_exporter_url + the legacy
// prometheus_labels map (used by the /sd service-discovery endpoint).
type PrometheusInfo struct {
	URL             string            `json:"url,omitempty"`
	NodeExporterURL string            `json:"node_exporter_url,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
}

// UserAttributes is the user-edited free-form key/value map. Stored as JSON
// in devices.user_attributes. The frontend renders it as an editable
// {key,value} panel (see web/src/lib/components/scanner/LabelEditor.svelte).
type UserAttributes map[string]string

// MarshalScanAttributes serializes a ScanAttributes into the JSON string the
// DB column holds. Empty struct → "{}" so the column never stores "null".
func MarshalScanAttributes(s ScanAttributes) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("marshal scan_attributes: %w", err)
	}
	return string(b), nil
}

// UnmarshalScanAttributes parses a scan_attributes JSON string. An empty or
// NULL column yields the zero value with no error.
func UnmarshalScanAttributes(raw string) (ScanAttributes, error) {
	var s ScanAttributes
	if raw == "" {
		return s, nil
	}
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return ScanAttributes{}, fmt.Errorf("unmarshal scan_attributes: %w", err)
	}
	return s, nil
}

// UnmarshalScanAttributesPtr is the sql.NullString variant for generated
// queries when a left join may produce NULL. Currently the scan_attributes
// column is NOT NULL DEFAULT '{}' so the plain string helper above suffices.
func UnmarshalScanAttributesPtr(v sql.NullString) (ScanAttributes, error) {
	if !v.Valid {
		return ScanAttributes{}, nil
	}
	return UnmarshalScanAttributes(v.String)
}

// MarshalUserAttributes serializes a UserAttributes map. nil/empty → "{}".
func MarshalUserAttributes(u UserAttributes) (string, error) {
	if len(u) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(u)
	if err != nil {
		return "", fmt.Errorf("marshal user_attributes: %w", err)
	}
	return string(b), nil
}

// UnmarshalUserAttributes parses a user_attributes JSON string into a map.
// Returns a non-nil (possibly empty) map.
func UnmarshalUserAttributes(raw string) (UserAttributes, error) {
	u := UserAttributes{}
	if raw == "" {
		return u, nil
	}
	if err := json.Unmarshal([]byte(raw), &u); err != nil {
		return UserAttributes{}, fmt.Errorf("unmarshal user_attributes: %w", err)
	}
	if u == nil {
		u = UserAttributes{}
	}
	return u, nil
}

// MergeUserAttributes applies a patch over base: patch's keys overwrite base
// (including empty-string values, which the caller can use to delete a key).
// Returns a new map; base and patch are not mutated.
func MergeUserAttributes(base UserAttributes, patch UserAttributes) UserAttributes {
	out := UserAttributes{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range patch {
		if v == "" {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

// ScanLastScannedTime parses the LastScannedAt RFC3339 string; returns the
// zero time when empty or unparseable. Convenience for callers that want a
// time.Time instead of a string.
func (s ScanAttributes) ScanLastScannedTime() time.Time {
	if s.LastScannedAt == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s.LastScannedAt)
	if err != nil {
		return time.Time{}
	}
	return t
}
