// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package scannerv2

import (
	"context"
	"database/sql"
)

// Repository is the ④ Persistence abstraction. The orchestrator and handlers
// depend only on this interface, never on sqlc types or *sql.DB. The concrete
// SQLite implementation lives in store/sqlite.go (Phase 1); tests use an
// in-memory fake.
//
// All methods are best-effort from the orchestrator's perspective: persistence
// failures are logged but never abort a scan. This keeps a slow/locked SQLite
// from blocking the detection pipeline.
type Repository interface {
	// RecordEvidence persists raw evidence (subject to sampling — see config
	// scanner.persist_raw_evidence). Implementations may no-op when disabled.
	RecordEvidence(ctx context.Context, ev []Evidence) error

	// RecordServices persists the classified service identities for an IP.
	// Replaces the prior set for the IP within the current scan run.
	RecordServices(ctx context.Context, ip string, services []ServiceIdentity) error

	// RecordDevice upserts the enriched device fields.
	RecordDevice(ctx context.Context, ip string, device DeviceRef) error

	// RecordHeartbeats persists heartbeat specs generated for the IP.
	// Implementations reconcile with existing configs (update vs insert).
	RecordHeartbeats(ctx context.Context, ip string, specs []HeartbeatSpec) error

	// RecordNeighbors persists L2 adjacency (LLDP/CDP/Bridge-MIB/ARP) for the
	// device at ip. Each NeighborSpec is one edge: the neighbor's MAC (the merge
	// key), the discovery protocol, and optional local/remote port labels.
	// Implementations upsert on (device_id, neighbor_mac, protocol), refreshing
	// last_seen without losing first_seen.
	RecordNeighbors(ctx context.Context, ip string, neighbors []NeighborSpec) error

	// EnrichDeviceByMAC updates vendor/model/type/hostname fields for a device
	// identified by MAC address. Only updates existing devices — no insert
	// (enrich-existing-only). Unknown keys go to scan_attributes JSON.
	// Returns nil if no device matches the MAC (not an error).
	EnrichDeviceByMAC(ctx context.Context, mac string, fields map[string]string) error

	// RecordTLSCerts persists the TLS certificate chain(s) collected for a
	// host:port during dispatch. Multiple ports produce one call with all rows;
	// within a (ip, port) pair the prior chain is replaced wholesale (delete +
	// insert in a tx) so stale certs don't linger when a server rotates.
	// Records carrying only an Error (handshake failed) are still persisted so
	// the UI can distinguish "we tried this port" from "port not scanned".
	// Best-effort like the other Record methods: persistence failures are
	// logged but never abort a scan.
	RecordTLSCerts(ctx context.Context, ip string, certs []TLSCertRecord) error

	// ResolveDeviceIdentity decides which devices row a scan should update, or
	// whether a new row must be created. It is the read-only half of the
	// MAC-primary identity upsert (the single authoritative writer for device
	// identity, runner.applyDeviceBridge). Identity is MAC-first across ALL
	// networks (a roaming device stays one asset), falling back to (ip,
	// network_id) when no MAC is known. It also detects two special cases the
	// caller must handle in ApplyDeviceIdentity:
	//   - Roamed: the MAC-matched device moved to a NEW free IP (DHCP renewal).
	//     The caller relocates the row's ip_address to the scanned IP.
	//   - ReplacedID: a different physical device now occupies the scanned IP
	//     (router/asset swap). The IP-holder becomes the update target and the
	//     prior MAC-matched row (ReplacedID) is superseded (marked offline).
	//
	// networkID is per-call: a center ingesting many agents' networks resolves
	// each against the agent's own network, not the center's. This method MUST
	// NOT mutate — the caller applies type stickiness between resolve and write
	// (see IdentityWrite), then calls ApplyDeviceIdentity to commit.
	ResolveDeviceIdentity(ctx context.Context, mac, ip string, networkID sql.NullInt64) (IdentityResolution, error)

	// ApplyDeviceIdentity commits the identity upsert for a resolved device: it
	// creates a new row (in.IsNew) or updates the resolved row (normal rescan,
	// device replacement when ReplacedID != 0, or IP roaming when Roamed). It
	// also stamps status=online, last_seen, offline_since=NULL, last_scanned_at,
	// and the mac/network — the liveness + freshness bookkeeping that belongs
	// with the identity write. Returns the device ID of the affected row.
	//
	// The caller (runner.applyDeviceBridge) computes the report-derived fields
	// (name, open_ports/services/scan_attributes JSON, tags, …) and the
	// stickiness-adjusted Type BEFORE calling this, so the implementation is a
	// thin SQL layer with no classification logic. in.TargetID MUST be the value
	// returned by ResolveDeviceIdentity (0 when IsNew).
	ApplyDeviceIdentity(ctx context.Context, in IdentityWrite) (deviceID int64, err error)
}

// IdentityResolution is the read-only result of ResolveDeviceIdentity. It tells
// the caller which existing row to update (TargetID) and which special handling
// applies (Roamed / ReplacedID), or that no row exists yet (IsNew).
type IdentityResolution struct {
	// TargetID is the devices.id to update. 0 when IsNew (no existing row).
	TargetID int64
	// ReplacedID is the id of a row superseded by a device replacement (a
	// different physical device took over the scanned IP). The implementation
	// marks it offline; 0 means no replacement.
	ReplacedID int64
	// Roamed is true when the MAC-matched device moved to a NEW free IP (DHCP
	// renewal/re-lease). The caller relocates ip_address to the scanned IP.
	Roamed bool
	// IsNew is true when no existing row matches → the caller must create one.
	IsNew bool
}

// IdentityWrite is the input to ApplyDeviceIdentity. It carries the identity
// resolution result (TargetID/IsNew/ReplacedID/Roamed) plus the pre-computed
// field values to persist. The runner derives the JSON blobs (OpenPortsJSON,
// ScanAttributesJSON, …) from the HostReport BEFORE calling ApplyDeviceIdentity,
// so the store stays a thin SQL layer.
type IdentityWrite struct {
	// Resolution (from ResolveDeviceIdentity).
	TargetID   int64 // 0 when IsNew
	IsNew      bool
	ReplacedID int64 // device replacement (router/asset swap); 0 = none
	Roamed     bool

	// Origin.
	IP        string
	MAC       string
	NetworkID sql.NullInt64

	// Identity + classification fields to persist.
	Name        string
	Type        string
	Brand       string
	Description string
	Location    string

	// Scan-derived JSON blobs (pre-computed by the runner).
	OpenPortsJSON        string
	DetectedServicesJSON string
	PrometheusURL        string
	NodeExporterURL      string
	ScanAttributesJSON   string
	TagsJSON             string
	RTTMs                int64
}

// NoopRepository is a Repository that does nothing. It is the default when no
// persistence is wired (e.g. unit tests, ad-hoc CLI scans).
type NoopRepository struct{}

func (NoopRepository) RecordEvidence(context.Context, []Evidence) error                   { return nil }
func (NoopRepository) RecordServices(context.Context, string, []ServiceIdentity) error    { return nil }
func (NoopRepository) RecordDevice(context.Context, string, DeviceRef) error              { return nil }
func (NoopRepository) RecordHeartbeats(context.Context, string, []HeartbeatSpec) error    { return nil }
func (NoopRepository) RecordNeighbors(context.Context, string, []NeighborSpec) error      { return nil }
func (NoopRepository) EnrichDeviceByMAC(context.Context, string, map[string]string) error { return nil }
func (NoopRepository) RecordTLSCerts(context.Context, string, []TLSCertRecord) error      { return nil }

// ResolveDeviceIdentity reports "new device" for every call — a Noop repository
// holds no rows, so identity resolution always signals create.
func (NoopRepository) ResolveDeviceIdentity(context.Context, string, string, sql.NullInt64) (IdentityResolution, error) {
	return IdentityResolution{IsNew: true}, nil
}

// ApplyDeviceIdentity is a no-op; returns 0 (no row created) and nil.
func (NoopRepository) ApplyDeviceIdentity(context.Context, IdentityWrite) (int64, error) {
	return 0, nil
}

// Compile-time check that NoopRepository satisfies Repository.
var _ Repository = NoopRepository{}
