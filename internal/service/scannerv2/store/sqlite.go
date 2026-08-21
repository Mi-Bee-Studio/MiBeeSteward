// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Package store provides the SQLite implementation of scannerv2.Repository.
//
// It uses raw database/sql (not sqlc) so the v2 persistence layer stays
// self-contained and queryable without the code-generation step. The v1
// sqlc-generated code (internal/db) remains untouched for the legacy engine.
//
// Tables (defined in db/schema.sql):
//   - service_evidence: raw probe evidence (sampled)
//   - host_services:    classified service identities per host
//   - devices:          enriched device fields (existing table, upserted)
//   - heartbeat_configs: generated heartbeat specs (existing table)
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"mibee-steward/internal/domain"

	"mibee-steward/internal/service/scannerv2"

	"github.com/google/uuid"
)

// SQLiteRepository implements scannerv2.Repository against a *sql.DB.
//
// persistRawEvidence gates writing to service_evidence (off by default to
// avoid storage bloat — see config scanner.persist_raw_evidence).
type SQLiteRepository struct {
	db                   *sql.DB
	logger               *slog.Logger
	persistRawEvidence   bool
	defaultHBInterval    int // seconds, 0 → leave config default
	defaultHBTimeout     int // seconds
	defaultSNMPCommunity string
	defaultSNMPOID       string
	// networkID tags every device this repository upserts with its origin
	// network (devices.network_id). 0 = unresolved/legacy (treated as NULL).
	// Two instances on different LANs thus keep their data partitioned even
	// when private IPs overlap. Resolved from config `network` at startup.
	networkID sql.NullInt64
	// uuidCache memoizes IP → device_uuid lookups within the repository's
	// lifetime. UUIDs are stable device identity (they never change once
	// assigned), so caching is correct; the set of IPs per network is bounded
	// (a /24 = 254 hosts), so the map does not grow unbounded. Without this
	// cache, a /24 scan with 50 alive hosts triggers ~200 DB round-trips just
	// to resolve UUIDs (RecordEvidence + RecordServices + RecordTLSCerts each
	// call resolveDeviceUUID per host). (#162)
	uuidCache map[string]string
	uuidMu    sync.Mutex
}

// Options configures the SQLiteRepository.
type Options struct {
	// PersistRawEvidence enables writing raw evidence to service_evidence.
	PersistRawEvidence bool
	// DefaultHeartbeatInterval is the interval (s) used when a HeartbeatSpec
	// leaves IntervalSeconds at 0.
	DefaultHeartbeatInterval int
	// DefaultHeartbeatTimeout is the timeout (s) used when a HeartbeatSpec
	// leaves TimeoutSeconds at 0.
	DefaultHeartbeatTimeout int
	// DefaultSNMPCommunity is applied to SNMP heartbeats that don't set one.
	DefaultSNMPCommunity string
	// DefaultSNMPOID is applied to SNMP heartbeats that don't set one.
	DefaultSNMPOID string
	// NetworkID is the networks.id this repository tags discovered devices
	// with. 0 leaves devices.network_id NULL (single-instance / unresolved).
	NetworkID int64
}

// NewSQLiteRepository constructs the repository. db must already have the
// v2 tables (service_evidence, host_services) — main.go applies schema.sql on
// startup, so this holds for the production path. For tests, ensure schema is
// applied to the in-memory DB.
func NewSQLiteRepository(db *sql.DB, opts Options, logger *slog.Logger) *SQLiteRepository {
	if logger == nil {
		logger = slog.Default()
	}
	var nid sql.NullInt64
	if opts.NetworkID > 0 {
		nid = sql.NullInt64{Int64: opts.NetworkID, Valid: true}
	}
	return &SQLiteRepository{
		db:                   db,
		logger:               logger,
		persistRawEvidence:   opts.PersistRawEvidence,
		defaultHBInterval:    opts.DefaultHeartbeatInterval,
		defaultHBTimeout:     opts.DefaultHeartbeatTimeout,
		defaultSNMPCommunity: opts.DefaultSNMPCommunity,
		defaultSNMPOID:       opts.DefaultSNMPOID,
		networkID:            nid,
		uuidCache:            make(map[string]string),
	}
}

// Compile-time interface check.
var _ scannerv2.Repository = (*SQLiteRepository)(nil)

// RecordEvidence inserts raw evidence rows. Sampling: when persistRawEvidence
// is false, the method is a no-op. Batches inserts in a single tx.
//
// device_uuid is resolved best-effort (the engine runs this BEFORE the runner
// persists the device row, so on first discovery the device may not exist yet —
// the row lands with device_uuid=” and is healed on the next scan / by the
// backfill migration). Steady-state scans (the common case) find the device.
func (r *SQLiteRepository) RecordEvidence(ctx context.Context, evs []scannerv2.Evidence) error {
	if !r.persistRawEvidence || len(evs) == 0 {
		return nil
	}
	// Resolve once per call: all rows in a batch share the same IP, so a single
	// lookup is enough. '' when unresolved (see method doc).
	var uuid string
	if len(evs) > 0 {
		uuid, _ = r.resolveDeviceUUID(ctx, evs[0].IP)
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO service_evidence (ip, device_uuid, source, kind, port, protocol, raw_data, confidence, observed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range evs {
		raw, err := json.Marshal(e.RawData)
		if err != nil {
			raw = []byte("{}")
		}
		ts := e.ObservedAt
		if ts.IsZero() {
			ts = time.Now()
		}
		if _, err := stmt.ExecContext(ctx, e.IP, uuid, e.Source, e.Kind, e.Port, e.Protocol, string(raw), e.Confidence, scannerv2.DBTime(ts)); err != nil {
			r.logger.Debug("insert evidence row failed", "error", err)
		}
	}
	return tx.Commit()
}

// RecordServices replaces the host's service-identity set atomically.
//
// Keyed by device_uuid (resolved from IP) so the service list follows a device
// across a DHCP roam instead of stranding on the old IP. On first discovery the
// device row may not exist yet (the engine runs before the runner persists the
// device); the rows land with device_uuid=” and are healed on the next scan.
// The DELETE keeps an IP guard as a belt-and-suspenders so a not-yet-uuid'd row
// set is still replaced rather than accumulated while the uuid is unresolved.
func (r *SQLiteRepository) RecordServices(ctx context.Context, ip string, services []scannerv2.ServiceIdentity) error {
	uuid, _ := r.resolveDeviceUUID(ctx, ip)

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// Replace the host's prior service set. The rows belong to this IP regardless
	// of their device_uuid state, so the DELETE keys on IP. This matters across
	// the uuid-resolution transition: scan 1 (no device row yet) lands rows with
	// device_uuid='', scan 2 (uuid resolved) must remove those rows — a DELETE
	// scoped to the resolved uuid would miss the device_uuid='' rows and the
	// subsequent INSERT would collide on UNIQUE(ip,service,port), silently
	// dropping the fresh data (regression #129).
	if _, err := tx.ExecContext(ctx, `DELETE FROM host_services WHERE ip = ?`, ip); err != nil {
		return err
	}
	if len(services) == 0 {
		return tx.Commit()
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO host_services (ip, device_uuid, service, port, protocol, confidence, metadata, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	// Deduplicate by (service, port): when multiple identities share the same
	// key (e.g. builtin http-presence + Recog http_header.server both emit
	// http/80), merge their metadata and keep the highest confidence. Without
	// this, the UNIQUE(ip,service,port) constraint causes 50+ warnings per scan.
	type svcKey struct {
		service string
		port    int
	}
	merged := make(map[svcKey]scannerv2.ServiceIdentity)
	for _, s := range services {
		k := svcKey{s.Service, s.Port}
		if existing, ok := merged[k]; ok {
			// Merge metadata: existing values win (first-write), add new keys.
			if existing.Metadata == nil {
				existing.Metadata = map[string]string{}
			}
			for mk, mv := range s.Metadata {
				if _, has := existing.Metadata[mk]; !has {
					existing.Metadata[mk] = mv
				}
			}
			if s.Confidence > existing.Confidence {
				existing.Confidence = s.Confidence
			}
			merged[k] = existing
		} else {
			merged[k] = s
		}
	}

	now := scannerv2.DBTime(time.Now())
	for _, s := range merged {
		meta, err := json.Marshal(s.Metadata)
		if err != nil {
			meta = []byte("{}")
		}
		if _, err := stmt.ExecContext(ctx, ip, uuid, s.Service, s.Port, s.Protocol, s.Confidence, string(meta), now); err != nil {
			r.logger.Warn("insert host_service row failed", "ip", ip, "service", s.Service, "error", err)
		}
	}
	return tx.Commit()
}

// RecordTLSCerts persists the TLS certificate chains collected for an IP. The
// prior set of rows for each (ip, port) is replaced wholesale (delete + insert
// in a tx) so a server that rotated its cert doesn't show stale data. Rows for
// ports not present in this call are left untouched (a partial scan of a 20-port
// host shouldn't wipe the other 18 ports' certs).
//
// Records carrying an Error are still inserted (with the typed columns empty) so
// the UI can render "we tried this port and the handshake failed" — this is the
// difference between "port scanned, no TLS" and "port not scanned at all".
func (r *SQLiteRepository) RecordTLSCerts(ctx context.Context, ip string, certs []scannerv2.TLSCertRecord) error {
	if len(certs) == 0 {
		return nil
	}
	uuid, _ := r.resolveDeviceUUID(ctx, ip)

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// Collect the distinct ports in this batch; delete prior rows for each.
	// Keyed by IP (not device_uuid): the cert chain belongs to whatever device
	// currently holds this IP, and across the uuid-resolution transition a
	// uuid-scoped DELETE would leave device_uuid='' rows from the first scan
	// behind, accumulating duplicates (the (ip,port) index is non-unique, so no
	// conflict — just stale rows). Mirrors the RecordServices fix (#129).
	ports := make(map[int]struct{}, len(certs))
	for _, c := range certs {
		ports[c.Port] = struct{}{}
	}
	for port := range ports {
		if _, err := tx.ExecContext(ctx, `DELETE FROM host_tls_certs WHERE ip = ? AND port = ?`, ip, port); err != nil {
			return err
		}
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO host_tls_certs (
			ip, device_uuid, port, cert_index,
			subject_cn, subject_org, subject, issuer_cn, issuer_org, issuer,
			san_dns, san_ip, san_email, serial,
			not_before, not_after,
			sig_algorithm, key_algorithm, key_bits, is_ca, self_signed,
			fingerprint_sha256, pem,
			tls_version, cipher_suite, trusted, error, updated_at
		) VALUES (?, ?, ?, ?,  ?, ?, ?, ?, ?, ?,  ?, ?, ?, ?,  ?, ?,  ?, ?, ?, ?, ?,  ?, ?,  ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := scannerv2.DBTime(time.Now())
	for _, c := range certs {
		if _, err := stmt.ExecContext(ctx,
			ip, uuid, c.Port, c.CertIndex,
			c.SubjectCN, c.SubjectOrg, c.Subject, c.IssuerCN, c.IssuerOrg, c.Issuer,
			c.SanDNS, c.SanIP, c.SanEmail, c.Serial,
			c.NotBefore, c.NotAfter,
			c.SigAlgorithm, c.KeyAlgorithm, c.KeyBits, boolToInt(c.IsCA), boolToInt(c.SelfSigned),
			c.FingerprintSHA256, c.PEM,
			c.TLSVersion, c.CipherSuite, boolToInt(c.Trusted), c.Error, now,
		); err != nil {
			r.logger.Warn("insert host_tls_certs row failed", "ip", ip, "port", c.Port, "error", err)
		}
	}
	return tx.Commit()
}

// boolToInt converts a bool to the integer encoding used by the schema's
// INTEGER columns (is_ca, self_signed, trusted). SQLite has no native bool.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// RecordDevice enriches an EXISTING device row with fields discovered by the
// pipeline. It deliberately does NOT create device identities, set status, set
// the display name, or detect device replacement — all of those are the
// responsibility of the single authoritative writer, runner.applyDeviceBridge.
//
// Why a "best-effort enrichment only" path exists alongside the runner: the
// orchestrator runs inside engine.ScanTargets (every caller: sync handler, the
// async runner, passive discovery). Persisting freshly-classified scan data
// here means it lands even on the paths that don't subsequently re-write the
// device. But because this never INSERTs, never writes name/status, and never
// does identity resolution that could conflict with the runner, it CANNOT
// produce the dual-write inconsistencies (unknown-status orphans, name
// clobbering, divergent scan_attributes shapes) that arose when it also owned
// device creation. The runner remains the sole authority for row lifecycle.
//
// If no existing row matches, this is a no-op (the runner will create the row).
func (r *SQLiteRepository) RecordDevice(ctx context.Context, ip string, d scannerv2.DeviceRef) error {
	// The devices table has many columns; v2 touches a known subset. Unknown
	// Fields keys are serialized into scan_attributes as a JSON extension to
	// avoid schema churn for experimental attributes. Stable keys map to
	// dedicated columns (and to top-level ScanAttributes fields below).
	extra := map[string]string{}
	openPorts := ""
	detectedServices := ""
	promURL := ""
	neURL := ""
	for k, v := range d.Fields {
		switch k {
		case "open_ports":
			openPorts = v
		case "detected_services":
			detectedServices = v
		case "prometheus_url":
			promURL = v
		case "node_exporter_url":
			neURL = v
		default:
			extra[k] = v
		}
	}
	if openPorts == "" {
		openPorts = "[]"
	}
	if detectedServices == "" {
		detectedServices = "[]"
	}
	// scan_attributes built from the DeviceRef Fields. The runner's
	// device_bridge.go produces the authoritative full ScanAttributes (with
	// OpenPorts/DetectedServices/SNMP structured sub-objects) via json_patch;
	// this store path runs first as pre-enrichment.
	scanAttrs := buildStoreScanAttributes(d, extra, openPorts, detectedServices, promURL, neURL)
	scanAttrsJSON, _ := domain.MarshalScanAttributes(scanAttrs)

	// Resolve an EXISTING row to enrich. MAC-primary (global), else (ip,
	// network_id). No INSERT on miss — device creation is the runner's job.
	mac := NormalizeMAC(extra["mac"])
	brand := d.Brand
	model := d.Model
	// NOTE: type is intentionally NOT enriched here. For local scans DeviceRef.Type
	// is always empty (handlers mutate Fields, not the Type field), so writing it
	// would force-overwrite the runner's authoritative type (set by
	// applyDeviceBridge's evidence-stickiness merge) back to a default on every
	// scan — the double-writer conflict that caused the other↔router type flap.
	// The runner (applyDeviceBridge) is the sole authority for devices.type;
	// this store path is best-effort enrichment only (see the package doc).

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var existingID int64
	switch {
	case mac != "":
		err = tx.QueryRowContext(ctx,
			`SELECT id FROM devices WHERE mac_address = ? LIMIT 1`, mac).Scan(&existingID)
		if err == sql.ErrNoRows {
			// No global MAC match → try (ip, network_id) so a device first seen
			// MAC-less (matched by IP) still gets enriched here.
			if r.networkID.Valid {
				err = tx.QueryRowContext(ctx,
					`SELECT id FROM devices WHERE ip_address = ? AND network_id = ? LIMIT 1`,
					ip, r.networkID.Int64).Scan(&existingID)
			} else {
				err = tx.QueryRowContext(ctx,
					`SELECT id FROM devices WHERE ip_address = ? AND network_id IS NULL LIMIT 1`,
					ip).Scan(&existingID)
			}
		}
	default:
		if r.networkID.Valid {
			err = tx.QueryRowContext(ctx,
				`SELECT id FROM devices WHERE ip_address = ? AND network_id = ? LIMIT 1`,
				ip, r.networkID.Int64).Scan(&existingID)
		} else {
			err = tx.QueryRowContext(ctx,
				`SELECT id FROM devices WHERE ip_address = ? AND network_id IS NULL LIMIT 1`,
				ip).Scan(&existingID)
		}
	}

	// No existing row → nothing to enrich. The runner will create the device.
	if err == sql.ErrNoRows {
		return tx.Commit()
	}
	if err != nil {
		r.logger.Warn("lookup device for enrichment failed", "ip", ip, "mac", mac, "error", err)
		return tx.Commit()
	}

	// Enrich the matched row. Only v2-managed enrichment columns: brand/model
	// (force-overwrite when non-empty), mac (fill when newly resolved),
	// open_ports/detected_services/prometheus/node_exporter, scan_attributes,
	// freshness timestamps. NOTE: name, type, status, description, location,
	// tags, and device replacement are intentionally NOT handled here — the
	// runner owns them. In particular type MUST stay out: this store path runs
	// BEFORE applyDeviceBridge, and writing type here defeated the runner's
	// CASE-WHEN guard (the type-flap root cause).
	now := scannerv2.DBTime(time.Now())
	if _, err = tx.ExecContext(ctx, `
			UPDATE devices SET
			    brand = CASE WHEN ? != '' THEN ? ELSE brand END,
			    model = CASE WHEN ? != '' THEN ? ELSE model END,
			    mac_address = CASE WHEN ? != '' THEN ? ELSE mac_address END,
			    open_ports = ?,
			    detected_services = ?,
			    prometheus_url = ?,
			    node_exporter_url = ?,
			    scan_attributes = ?,
			    last_seen = ?,
			    last_scanned_at = ?,
			    updated_at = ?
			WHERE id = ?`,
		brand, brand, model, model,
		mac, mac,
		openPorts, detectedServices, promURL, neURL, string(scanAttrsJSON),
		now, now, now, existingID); err != nil {
		r.logger.Warn("enrich device failed", "ip", ip, "mac", mac, "error", err)
	}

	return tx.Commit()
}

// identityNetworkClause returns the SQL fragment + arg matching the
// resolveDeviceIdentity / ApplyDeviceIdentity network scoping: "network_id = ?"
// when the per-call network is valid, "network_id IS NULL" when not. Unlike
// RecordDevice (which uses the repository's own r.networkID field), the identity
// methods take a per-call networkID so a center ingesting many agents' networks
// resolves each against the agent's own network.
func identityNetworkClause(networkID sql.NullInt64) (string, []any) {
	if networkID.Valid {
		return "network_id = ?", []any{networkID.Int64}
	}
	return "network_id IS NULL", nil
}

// ResolveDeviceIdentity is the read-only half of the MAC-primary identity
// upsert. It is the single authoritative resolver for which devices row a scan
// should update (or whether a new row must be created), ported verbatim from the
// former runner.resolveDeviceIdentity. See Repository.ResolveDeviceIdentity for
// the contract; the IsNew field replaces the former sql.ErrNoRows sentinel so
// callers switch on a value, not an error.
//
// networkID is per-call (the agent's network on the center ingestion path, the
// instance's own network locally) — it is NOT r.networkID, so one center
// repository can resolve identities across many networks.
func (r *SQLiteRepository) ResolveDeviceIdentity(ctx context.Context, mac, ip string, networkID sql.NullInt64) (scannerv2.IdentityResolution, error) {
	if mac == "" {
		// No MAC → identity is (ip, network_id).
		var targetID int64
		var err error
		if networkID.Valid {
			err = r.db.QueryRowContext(ctx,
				`SELECT id FROM devices WHERE ip_address = ? AND network_id = ? LIMIT 1`,
				ip, networkID.Int64).Scan(&targetID)
		} else {
			err = r.db.QueryRowContext(ctx,
				`SELECT id FROM devices WHERE ip_address = ? AND network_id IS NULL LIMIT 1`,
				ip).Scan(&targetID)
		}
		if err == sql.ErrNoRows {
			return scannerv2.IdentityResolution{IsNew: true}, nil
		}
		if err != nil {
			return scannerv2.IdentityResolution{}, err
		}
		return scannerv2.IdentityResolution{TargetID: targetID}, nil
	}

	// MAC present → global identity lookup.
	var targetID int64
	err := r.db.QueryRowContext(ctx,
		`SELECT id FROM devices WHERE mac_address = ? LIMIT 1`, mac).Scan(&targetID)
	if err == sql.ErrNoRows {
		// MAC not seen before. Fall back to (ip, network_id) with empty mac so a
		// device first seen MAC-less gets its mac filled on this scan.
		if networkID.Valid {
			err = r.db.QueryRowContext(ctx,
				`SELECT id FROM devices WHERE ip_address = ? AND network_id = ? AND mac_address = '' LIMIT 1`,
				ip, networkID.Int64).Scan(&targetID)
		} else {
			err = r.db.QueryRowContext(ctx,
				`SELECT id FROM devices WHERE ip_address = ? AND network_id IS NULL AND mac_address = '' LIMIT 1`,
				ip).Scan(&targetID)
		}
		if err == sql.ErrNoRows {
			return scannerv2.IdentityResolution{IsNew: true}, nil
		}
		if err != nil {
			return scannerv2.IdentityResolution{}, err
		}
		return scannerv2.IdentityResolution{TargetID: targetID}, nil
	}
	if err != nil {
		return scannerv2.IdentityResolution{}, err
	}

	// MAC matched a row. Check whether it sits on the scanned ip; if so, this is
	// the normal update path (no replacement).
	var macRowIP string
	var macRowMAC string
	if qerr := r.db.QueryRowContext(ctx,
		`SELECT ip_address, mac_address FROM devices WHERE id = ?`, targetID).Scan(&macRowIP, &macRowMAC); qerr != nil {
		// Failing to read the row's ip is unexpected; proceed with the plain match.
		return scannerv2.IdentityResolution{TargetID: targetID}, nil
	}
	if macRowIP == ip {
		return scannerv2.IdentityResolution{TargetID: targetID}, nil // same ip — normal update.
	}

	// MAC matched a device on a DIFFERENT ip than the one being scanned. Check
	// whether the scanned ip is held by another device with its own different
	// mac: that signals a device replacement.
	var ipHolderID int64
	var ipHolderMAC string
	var ipLookErr error
	if networkID.Valid {
		ipLookErr = r.db.QueryRowContext(ctx,
			`SELECT id, mac_address FROM devices WHERE ip_address = ? AND network_id = ? LIMIT 1`,
			ip, networkID.Int64).Scan(&ipHolderID, &ipHolderMAC)
	} else {
		ipLookErr = r.db.QueryRowContext(ctx,
			`SELECT id, mac_address FROM devices WHERE ip_address = ? AND network_id IS NULL LIMIT 1`,
			ip).Scan(&ipHolderID, &ipHolderMAC)
	}
	if ipLookErr == sql.ErrNoRows {
		// Scanned ip is free → roaming: the MAC-matched device moved to a new IP.
		return scannerv2.IdentityResolution{TargetID: targetID, Roamed: true}, nil
	}
	if ipLookErr != nil {
		// Lookup error → don't speculate; fall back to the plain MAC match.
		return scannerv2.IdentityResolution{TargetID: targetID}, nil
	}
	// Replacement requires the ip-holder to have its OWN mac differing from the
	// scanned one. An empty-mac ip-holder is a MAC-less placeholder: leave it to
	// be filled, do not treat as a replacement conflict.
	if ipHolderMAC == "" || ipHolderMAC == mac {
		return scannerv2.IdentityResolution{TargetID: targetID}, nil
	}
	// Device replacement: the ip-holder becomes the target, the MAC-matched row
	// (the prior asset now sitting on a stale ip) is superseded.
	return scannerv2.IdentityResolution{TargetID: ipHolderID, ReplacedID: targetID}, nil
}

// existingIdentityUpdate is the static UPDATE for an existing device (normal
// rescan). Ported verbatim from the former runner.buildExistingUpdate. Positional
// args are assembled in identityUpdateArgs. scan_attributes uses json_patch (not a
// blind overwrite) so a SHALLOW scan can't erase fields a DEEPER earlier scan
// collected: json_patch(old, new) keeps old's keys that new omits.
func existingIdentityUpdate() string {
	return `
		UPDATE devices SET
		    name = CASE WHEN (name = '' OR name = ip_address) THEN ? ELSE name END,
		    type = CASE WHEN (type = '' OR type = 'unknown' OR type = 'other') AND ? != '' THEN ? ELSE type END,
		    brand = CASE WHEN (brand = '' OR brand = 'unknown') AND ? != '' THEN ? ELSE brand END,
		    description = CASE WHEN (description = '' OR description = 'unknown') AND ? != '' THEN ? ELSE description END,
		    location = CASE WHEN (location = '' OR location = 'unknown') AND ? != '' THEN ? ELSE location END,
		    open_ports = ?,
		    detected_services = ?,
		    prometheus_url = CASE WHEN ? != '' THEN ? ELSE prometheus_url END,
		    node_exporter_url = CASE WHEN ? != '' THEN ? ELSE node_exporter_url END,
		    scan_attributes = json_patch(scan_attributes, ?),
		    last_scan_rtt_ms = ?,
		    last_scanned_at = ?,
		    updated_at = ?
		WHERE id = ?`
}

// replacementIdentityUpdate is the UPDATE for the device-REPLACEMENT case (a
// different physical device now occupies this ip). FORCE-OVERWRITES
// name/type/brand/description/location — the CASE "only fill empty/unknown"
// guards that protect a re-scan would be WRONG here. Ported verbatim from the
// former runner.buildReplacementUpdate. Shares the SAME positional arg order as
// existingIdentityUpdate, so it reuses identityUpdateArgs.
func replacementIdentityUpdate() string {
	return `
		UPDATE devices SET
		    name = ?,
		    type = CASE WHEN ? != '' THEN ? ELSE type END,
		    brand = CASE WHEN ? != '' THEN ? ELSE brand END,
		    description = CASE WHEN ? != '' THEN ? ELSE description END,
		    location = CASE WHEN ? != '' THEN ? ELSE location END,
		    open_ports = ?,
		    detected_services = ?,
		    prometheus_url = CASE WHEN ? != '' THEN ? ELSE prometheus_url END,
		    node_exporter_url = CASE WHEN ? != '' THEN ? ELSE node_exporter_url END,
		    scan_attributes = json_patch(scan_attributes, ?),
		    last_scan_rtt_ms = ?,
		    last_scanned_at = ?,
		    updated_at = ?
		WHERE id = ?`
}

// identityUpdateArgs builds the positional args matching both
// existingIdentityUpdate and replacementIdentityUpdate (they share the same
// placeholder layout for the columns they have in common). Values come from the
// IdentityWrite (the runner pre-computes name/JSON blobs/type before calling).
func identityUpdateArgs(in scannerv2.IdentityWrite, now string) []any {
	return []any{
		in.Name, in.Type, in.Type,
		in.Brand, in.Brand,
		in.Description, in.Description,
		in.Location, in.Location,
		in.OpenPortsJSON, in.DetectedServicesJSON,
		in.PrometheusURL, in.PrometheusURL,
		in.NodeExporterURL, in.NodeExporterURL,
		in.ScanAttributesJSON,
		in.RTTMs, now, now, in.TargetID,
	}
}

// ApplyDeviceIdentity commits the identity upsert. Ported verbatim from the
// former runner.createDevice + the status/mac/roam/replacement UPDATE blocks of
// runner.applyDeviceBridge: creates a new row (in.IsNew) or updates the resolved
// row (normal rescan / replacement when ReplacedID != 0 / roam when Roamed),
// then stamps status/mac/last_seen and runs the roam eviction-retry. No
// transaction (mirrors the former best-effort, log-and-continue semantics). See
// Repository.ApplyDeviceIdentity for the contract.
func (r *SQLiteRepository) ApplyDeviceIdentity(ctx context.Context, in scannerv2.IdentityWrite) (int64, error) {
	if in.IsNew {
		return r.createDeviceIdentity(ctx, in)
	}
	return r.updateDeviceIdentity(ctx, in)
}

// createDeviceIdentity inserts a new device row. Ported verbatim from the former
// runner.createDevice; the values arrive pre-computed in the IdentityWrite.
func (r *SQLiteRepository) createDeviceIdentity(ctx context.Context, in scannerv2.IdentityWrite) (int64, error) {
	devType := in.Type
	if devType == "" {
		devType = "other"
	}
	now := scannerv2.DBTime(time.Now())
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO devices (device_uuid, name, type, brand, ip_address, mac_address,
		                     status, scan_source, description, location,
		                     open_ports, detected_services, prometheus_url, node_exporter_url,
		                     scan_attributes, network_id, first_seen, last_seen,
		                     tags, last_scan_rtt_ms, last_scanned_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?,
		        'online', 'scanner_v2', ?, ?,
		        ?, ?, ?, ?,
		        ?, ?, ?, ?,
		        ?, ?, ?, ?, ?)`,
		uuid.NewString(), in.Name, devType, in.Brand, in.IP, in.MAC,
		in.Description, in.Location,
		in.OpenPortsJSON, in.DetectedServicesJSON, in.PrometheusURL, in.NodeExporterURL,
		in.ScanAttributesJSON, in.NetworkID, now, now,
		in.TagsJSON, in.RTTMs, now, now, now)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// updateDeviceIdentity updates an existing resolved row: the identity-field
// UPDATE (existing vs replacement variant) followed by the status/mac/last_seen
// stamping and roam eviction-retry. Ported verbatim from the former
// runner.applyDeviceBridge existing-device branch.
func (r *SQLiteRepository) updateDeviceIdentity(ctx context.Context, in scannerv2.IdentityWrite) (int64, error) {
	// 1. Identity-field UPDATE (existing vs replacement variant).
	updateSQL := existingIdentityUpdate()
	if in.ReplacedID != 0 {
		updateSQL = replacementIdentityUpdate()
	}
	now := scannerv2.DBTime(time.Now())
	if _, uerr := r.db.ExecContext(ctx, updateSQL, identityUpdateArgs(in, now)...); uerr != nil {
		r.logger.Warn("device identity: update device failed", "ip", in.IP, "mac", in.MAC, "error", uerr)
	}

	// 2. Status/mac/last_seen stamping + roam relocation / replacement offline.
	if in.ReplacedID != 0 {
		// Replacement: force-overwrite mac on the ip-holder (it now belongs to the
		// scanned device), and mark the prior mac-matched row offline.
		_, _ = r.db.ExecContext(ctx, `
			UPDATE devices SET status='online',
			    mac_address = ?,
			    last_seen = ?,
			    offline_since=NULL,
			    last_scanned_at = ?, updated_at = ? WHERE id=?`,
			in.MAC, now, now, now, in.TargetID)
		_, _ = r.db.ExecContext(ctx,
			`UPDATE devices SET status='offline',
			    offline_since = CASE WHEN status != 'offline' THEN ? ELSE offline_since END,
			    updated_at=? WHERE id=?`,
			now, now, in.ReplacedID)
		r.logger.Warn("device identity: device replaced (router/asset swap detected)",
			"ip", in.IP, "scanned_mac", in.MAC, "replaced_device_id", in.ReplacedID,
			"target_device_id", in.TargetID,
			"action", "ip-holder updated with new mac; prior mac-matched row marked offline")
	} else {
		// Normal re-scan. When the device ROAMED (same MAC, new free IP — DHCP
		// renewal), relocate ip_address to the scanned IP.
		ipClause := "ip_address = ip_address"
		if in.Roamed {
			ipClause = "ip_address = ?"
		}
		_, err := r.db.ExecContext(ctx, `
			UPDATE devices SET status='online',
			    `+ipClause+`,
			    mac_address = CASE WHEN ? != '' AND mac_address = '' THEN ? ELSE mac_address END,
			    last_seen = ?,
			    offline_since=NULL,
			    last_scanned_at = ?, updated_at = ? WHERE id=?`,
			roamUpdateArgs(in.Roamed, in.IP, in.MAC, now, in.TargetID)...)
		if err != nil && in.Roamed {
			// The roam UPDATE can fail the (ip_address, network_id) unique constraint
			// when a mac='' placeholder occupies the target IP. Evict the placeholder
			// then retry (the real device with this MAC is taking over).
			r.logger.Warn("device identity: roam update failed, evicting ip-holder placeholder and retrying",
				"ip", in.IP, "device_id", in.TargetID, "error", err)
			if netClause, netArg := identityNetworkClause(in.NetworkID); netClause != "" {
				_, _ = r.db.ExecContext(ctx,
					`DELETE FROM devices WHERE ip_address = ? AND `+netClause+` AND mac_address = '' AND id != ?`,
					append([]any{in.IP}, append(netArg, in.TargetID)...)...)
			}
			_, err = r.db.ExecContext(ctx, `
				UPDATE devices SET status='online', ip_address = ?,
				    mac_address = CASE WHEN ? != '' AND mac_address = '' THEN ? ELSE mac_address END,
				    last_seen = ?,
				    offline_since=NULL,
				    last_scanned_at = ?, updated_at = ? WHERE id=?`,
				in.IP, in.MAC, in.MAC, now, now, now, in.TargetID)
			if err != nil {
				r.logger.Warn("device identity: roam retry failed", "ip", in.IP, "device_id", in.TargetID, "error", err)
			}
		}
	}
	return in.TargetID, nil
}

// roamUpdateArgs builds the positional args for the normal-rescan status UPDATE
// (mirrors the former runner.argsForRoamUpdate). When roamed is true the SQL has
// an extra `ip_address = ?` clause (the scanned IP comes first); otherwise
// ip_address is left unchanged.
func roamUpdateArgs(roamed bool, ip, mac string, now string, existingID int64) []any {
	if roamed {
		// order: ip_address=?, mac CASE ?/?, last_seen=?, last_scanned_at=?, updated_at=?, id=?
		return []any{ip, mac, mac, now, now, now, existingID}
	}
	// order: mac CASE ?/?, last_seen=?, last_scanned_at=?, updated_at=?, id=?
	return []any{mac, mac, now, now, now, existingID}
}

// NormalizeMAC canonicalizes a MAC address for storage and lookup: lowercased
// with colon separators (aa:bb:cc:dd:ee:ff). Empty/invalid input returns "".
// Shared by the store and runner so both upsert paths agree on the MAC key —
// without this, a MAC stored as "AA-BB..." would never match "aa:bb...".
func NormalizeMAC(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	// Accept colon/dash/space-separated and bare hex; normalize to colon form.
	hex := strings.NewReplacer(":", "", "-", "", " ", "", ".", "").Replace(s)
	if len(hex) != 12 {
		return ""
	}
	for _, c := range hex {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex[i : i+2])
	}
	return b.String()
}

// macBitSet reports whether the MAC's first-octet bit `mask` (0x02 for the
// locally-administered bit, 0x01 for the multicast bit) is set. The input must
// be in NormalizeMAC's canonical "aa:bb:cc:dd:ee:ff" form: bit 0 and bit 1 of
// the first octet both live in its second hex digit (mac[1]), so a single nibble
// parse is enough. Returns false for anything that isn't a canonical MAC.
func macBitSet(mac string, mask byte) bool {
	// A canonical MAC is exactly 17 chars ("aa:bb:cc:dd:ee:ff"); mac[1] is the
	// low nibble of the first octet, which encodes both the multicast (0x01) and
	// locally-administered (0x02) bits.
	if len(mac) < 17 {
		return false
	}
	d := mac[1]
	var n byte
	switch {
	case d >= '0' && d <= '9':
		n = d - '0'
	case d >= 'a' && d <= 'f':
		n = d - 'a' + 10
	default:
		return false
	}
	return n&mask != 0
}

// IsLocallyAdministeredMAC reports whether the MAC has the
// locally-administered (U/L) bit set (first octet bit 1, 0x02). This is a
// neutral factual statement about the IEEE 802 / RFC 7042 U/L bit: when set,
// the MAC was assigned locally rather than drawn from an IEEE OUI/MA-S/MA-M
// block. Note the bit CANNOT distinguish the two real-world causes — privacy
// randomization (iOS/Android/Windows; unstable across scans) vs. a locally
// fixed setting (soft-router/manual/hypervisor; stable) — so callers must NOT
// treat this as a "randomized" verdict or a stability/identity decision. The
// input must be canonical (NormalizeMAC).
func IsLocallyAdministeredMAC(mac string) bool {
	return macBitSet(mac, 0x2)
}

// IsMulticastMAC reports whether the MAC has the multicast bit set (first octet
// bit 0, 0x01). A unicast device should never transmit from a multicast source
// MAC; flagging it is a data-hygiene signal, not an identity decision. The input
// must be canonical (NormalizeMAC).
func IsMulticastMAC(mac string) bool {
	return macBitSet(mac, 0x1)
}

// buildStoreScanAttributes builds the engine-written scan_attributes document
// from a DeviceRef. It constructs a domain.ScanAttributes struct (NOT a loose
// map) so the JSON shape round-trips cleanly through UnmarshalScanAttributes —
// stringified numbers in the previous map made the API layer's int64-typed
// struct fields fail to deserialize, producing empty scan_attributes in
// responses even when the DB held data.
//
// Because the store path only sees a DeviceRef (no Evidence/Services arrays),
// structured sub-objects are best-effort: OpenPorts/DetectedServices are parsed
// from the raw JSON the caller captured, and any field not yet promoted to a
// typed ScanAttributes field lands under Extras.
//
// NOTE: keep the field mapping in sync with runner.buildScanAttributes when
// adding fields.
func buildStoreScanAttributes(d scannerv2.DeviceRef, extra map[string]string, openPorts, detectedServices, promURL, neURL string) domain.ScanAttributes {
	// Vendor: DeviceRef.Brand is set by some handlers, but the orchestrator's
	// evidence fold (OUI/cert-derived vendor) lands in Fields["inferred_brand"].
	// Prefer the explicit Brand, then fall back to the inferred value.
	vendor := d.Brand
	if vendor == "" {
		vendor = extra["inferred_brand"]
	}
	attr := domain.ScanAttributes{
		ScanSource:          "scanner_v2",
		InferredType:        d.Type,
		Vendor:              vendor,
		OUIPrefix:           extra["oui_prefix"],
		OUIVendor:           extra["oui_vendor"],
		InferredDescription: extra["inferred_description"],
		OS:                  extra["os_type"],
		OSVersion:           extra["os_version"],
		KernelVersion:       extra["kernel_version"],
		FirmwareVersion:     extra["firmware_version"],
		Hostname:            firstNonEmptyStore(extra["node_hostname"], extra["sys_name"]),
		MAC:                 extra["mac"],
	}
	// Numeric fields must be real numbers (not strings) so the typed struct
	// deserializes on read.
	if v, err := strconv.ParseInt(extra["memory_total_bytes"], 10, 64); err == nil && v > 0 {
		attr.MemoryTotalBytes = v
	}
	if v, err := strconv.Atoi(extra["cpu_count"]); err == nil && v > 0 {
		attr.CPUCount = v
	}
	if v, err := strconv.ParseInt(extra["uptime_seconds"], 10, 64); err == nil && v > 0 {
		attr.UptimeSeconds = v
	}

	// Pass through the JSON arrays the caller captured. They may already be
	// valid JSON ("[{...}]") or empty. Decode into the typed element slices.
	if openPorts != "" && openPorts != "[]" {
		var arr []domain.OpenPortEntry
		if json.Unmarshal([]byte(openPorts), &arr) == nil {
			attr.OpenPorts = arr
		}
	}
	if detectedServices != "" && detectedServices != "[]" {
		var arr []domain.ServiceEntry
		if json.Unmarshal([]byte(detectedServices), &arr) == nil {
			attr.DetectedServices = arr
		}
	}
	if promURL != "" || neURL != "" {
		attr.Prometheus = &domain.PrometheusInfo{URL: promURL, NodeExporterURL: neURL}
	}

	// Anything else the handler set that isn't a known key lands under extras,
	// preserving the previous "prometheus_labels JSON extension" intent but
	// moved to scan_attributes.extras so it's visibly scan data, not labels.
	known := map[string]bool{
		"inferred_type": true, "inferred_brand": true, "inferred_description": true,
		"os_type": true, "os_version": true, "kernel_version": true, "firmware_version": true,
		"node_hostname": true, "sys_name": true, "mac": true,
		"oui_prefix": true, "oui_vendor": true,
		"memory_total_bytes": true, "cpu_count": true, "uptime_seconds": true,
		"inferred_location": true,
	}
	extras := map[string]string{}
	for k, v := range extra {
		if !known[k] && v != "" {
			extras[k] = v
		}
	}
	if len(extras) > 0 {
		attr.Extras = extras
	}
	return attr
}

func firstNonEmptyStore(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// RecordHeartbeats reconciles generated heartbeat specs with existing
// heartbeat_configs for the device matched by IP. New methods are inserted;
// existing same-method configs are updated. The legacy schema keys configs by
// device_id (not IP), so we resolve device_id first.
func (r *SQLiteRepository) RecordHeartbeats(ctx context.Context, ip string, specs []scannerv2.HeartbeatSpec) error {
	if len(specs) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// Resolve device_id for the IP. If no device, skip (device creation is
	// RecordDevice's job; if it didn't run/persist yet, heartbeats are
	// retried on the next scan).
	var deviceID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM devices WHERE ip_address = ? LIMIT 1`, ip).Scan(&deviceID); err != nil {
		if err == sql.ErrNoRows {
			r.logger.Debug("record heartbeats: no device for ip", "ip", ip)
			return tx.Rollback() //nolint:errcheck
		}
		return err
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO heartbeat_configs (device_id, method, target, interval_seconds, timeout_seconds, snmp_community, snmp_oid, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1)
		ON CONFLICT(device_id, method) DO UPDATE SET
			target = excluded.target,
			interval_seconds = excluded.interval_seconds,
			timeout_seconds = excluded.timeout_seconds,
			snmp_community = excluded.snmp_community,
			snmp_oid = excluded.snmp_oid`)
	if err != nil {
		// The unique constraint (device_id, method) may not exist in the
		// legacy schema; fall back to check-then-upsert per spec.
		return r.legacyUpsertHeartbeats(ctx, tx, deviceID, specs)
	}
	defer stmt.Close()

	for _, s := range specs {
		interval := s.IntervalSeconds
		if interval == 0 {
			interval = r.defaultHBInterval
		}
		timeout := s.TimeoutSeconds
		if timeout == 0 {
			timeout = r.defaultHBTimeout
		}
		community := s.SNMPCommunity
		if community == "" {
			community = r.defaultSNMPCommunity
		}
		oid := s.SNMPOID
		if oid == "" {
			oid = r.defaultSNMPOID
		}
		if _, err := stmt.ExecContext(ctx, deviceID, s.Method, s.Target, interval, timeout, community, oid); err != nil {
			r.logger.Debug("upsert heartbeat failed", "ip", ip, "method", s.Method, "error", err)
		}
	}
	return tx.Commit()
}

// legacyUpsertHeartbeats is the fallback when the (device_id, method) unique
// index is absent: check-then-update-or-insert per spec.
func (r *SQLiteRepository) legacyUpsertHeartbeats(ctx context.Context, tx *sql.Tx, deviceID int64, specs []scannerv2.HeartbeatSpec) error {
	upd, err := tx.PrepareContext(ctx, `
		UPDATE heartbeat_configs SET target=?, interval_seconds=?, timeout_seconds=?, snmp_community=?, snmp_oid=?
		WHERE device_id=? AND method=?`)
	if err != nil {
		return err
	}
	defer upd.Close()

	ins, err := tx.PrepareContext(ctx, `
		INSERT INTO heartbeat_configs (device_id, method, target, interval_seconds, timeout_seconds, snmp_community, snmp_oid, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1)`)
	if err != nil {
		return err
	}
	defer ins.Close()

	for _, s := range specs {
		interval := s.IntervalSeconds
		if interval == 0 {
			interval = r.defaultHBInterval
		}
		timeout := s.TimeoutSeconds
		if timeout == 0 {
			timeout = r.defaultHBTimeout
		}
		community := s.SNMPCommunity
		if community == "" {
			community = r.defaultSNMPCommunity
		}
		oid := s.SNMPOID
		if oid == "" {
			oid = r.defaultSNMPOID
		}
		var existing int64
		_ = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM heartbeat_configs WHERE device_id=? AND method=?`, deviceID, s.Method).Scan(&existing)
		if existing > 0 {
			_, err := upd.ExecContext(ctx, s.Target, interval, timeout, community, oid, deviceID, s.Method)
			if err != nil {
				r.logger.Warn("update heartbeat failed", "device_id", deviceID, "method", s.Method, "error", err)
			}
		} else {
			_, err := ins.ExecContext(ctx, deviceID, s.Method, s.Target, interval, timeout, community, oid)
			if err != nil {
				r.logger.Warn("insert heartbeat failed", "device_id", deviceID, "method", s.Method, "error", err)
			}
		}
	}
	return tx.Commit()
}

// RecordNeighbors persists L2 adjacency edges (LLDP/CDP/Bridge-MIB/ARP) for the
// device at ip. It resolves ip → device_id (MAC-primary, then (ip, network_id)
// fallback — same identity rule as RecordDevice), then upserts each neighbor on
// (device_id, neighbor_mac, protocol). The neighbor's MAC is the cross-agent
// merge key; neighbor_device_id is left NULL (reconciled later when/if the
// neighbor is scanned). Best-effort: failures are logged, never abort a scan.
func (r *SQLiteRepository) RecordNeighbors(ctx context.Context, ip string, neighbors []scannerv2.NeighborSpec) error {
	if len(neighbors) == 0 {
		return nil
	}
	deviceID, err := r.resolveDeviceID(ctx, ip)
	if err != nil || deviceID == 0 {
		// Device not yet persisted (the orchestrator may call RecordNeighbors
		// before RecordDevice lands). Skip — the next scan re-discovers.
		r.logger.Debug("record neighbors: device not found", "ip", ip)
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	now := scannerv2.DBTime(time.Now())
	var networkID sql.NullInt64
	_ = tx.QueryRowContext(ctx, `SELECT network_id FROM devices WHERE id = ?`, deviceID).Scan(&networkID)

	for _, n := range neighbors {
		if n.NeighborMAC == "" || n.Protocol == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO device_neighbors (device_id, neighbor_mac, protocol, local_port, remote_port, network_id, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(device_id, neighbor_mac, protocol) DO UPDATE SET
				local_port = CASE WHEN excluded.local_port != '' THEN excluded.local_port ELSE device_neighbors.local_port END,
				remote_port = CASE WHEN excluded.remote_port != '' THEN excluded.remote_port ELSE device_neighbors.remote_port END,
				last_seen = excluded.last_seen`,
			deviceID, n.NeighborMAC, n.Protocol, n.LocalPort, n.RemotePort, networkID, now, now); err != nil {
			r.logger.Debug("upsert neighbor failed", "ip", ip, "neighbor_mac", n.NeighborMAC, "error", err)
		}
	}
	return tx.Commit()
}

// EnrichDeviceByMAC updates vendor/model/type/hostname fields for a device
// identified by MAC address. Only non-empty fields are applied; existing values
// are preserved for empty-string keys. Unknown keys are merged into
// scan_attributes.extras. Returns nil when no device matches the MAC.
func (r *SQLiteRepository) EnrichDeviceByMAC(ctx context.Context, mac string, fields map[string]string) error {
	mac = NormalizeMAC(mac)
	if mac == "" || len(fields) == 0 {
		return nil
	}

	// Look up device by MAC; return nil if not found (enrich-existing-only).
	var deviceID int64
	var scanAttrsRaw string
	err := r.db.QueryRowContext(ctx,
		`SELECT id, COALESCE(scan_attributes, '{}') FROM devices WHERE mac_address = ? LIMIT 1`, mac).Scan(&deviceID, &scanAttrsRaw)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}

	// Parse known and unknown fields.
	vendor := fields["vendor"]
	model := fields["model"]
	name := fields["hostname"]
	if name == "" {
		name = fields["sys_name"]
	}

	// Remaining unknown keys go into scan_attributes.extras.
	unknown := make(map[string]string)
	// "known" lists Fields keys that map to typed scan_attributes columns (or are
	// otherwise handled) and must NOT leak into the free-form Extras panel. Keep
	// in sync with the ScanAttributes struct + the orchestrator's evidence fold.
	known := map[string]bool{
		"vendor": true, "model": true, "type": true, "hostname": true, "sys_name": true,
		"mac": true, "oui_prefix": true, "oui_vendor": true,
	}
	for k, v := range fields {
		if !known[k] && v != "" {
			unknown[k] = v
		}
	}

	// Merge unknown keys into existing scan_attributes.extras.
	var scanAttrsJSON string
	if len(unknown) > 0 {
		attrs, err := domain.UnmarshalScanAttributes(scanAttrsRaw)
		if err != nil {
			attrs = domain.ScanAttributes{}
		}
		if attrs.Extras == nil {
			attrs.Extras = make(map[string]string)
		}
		for k, v := range unknown {
			attrs.Extras[k] = v
		}
		out, err := domain.MarshalScanAttributes(attrs)
		if err != nil {
			return err
		}
		scanAttrsJSON = out
	} else {
		scanAttrsJSON = scanAttrsRaw // unchanged
	}

	now := scannerv2.DBTime(time.Now())
	_, err = r.db.ExecContext(ctx, `
		UPDATE devices SET
		    brand = CASE WHEN ? != '' THEN ? ELSE brand END,
		    model = CASE WHEN ? != '' THEN ? ELSE model END,
		    name = CASE WHEN ? != '' THEN ? ELSE name END,
		    scan_attributes = ?,
		    updated_at = ?
		WHERE id = ?`,
		vendor, vendor, model, model, name, name,
		scanAttrsJSON, now, deviceID)
	return err
}

// resolveDeviceID finds the devices.id for an IP using the MAC-primary →
// (ip, network_id) identity rule. Returns 0 if the device doesn't exist yet.
func (r *SQLiteRepository) resolveDeviceID(ctx context.Context, ip string) (int64, error) {
	// Try by IP + this repo's network first (the common case — the device was
	// upserted by RecordDevice on this scan or a prior one).
	if r.networkID.Valid {
		var id int64
		err := r.db.QueryRowContext(ctx,
			`SELECT id FROM devices WHERE ip_address = ? AND network_id = ? LIMIT 1`, ip, r.networkID.Int64).Scan(&id)
		if err == nil {
			return id, nil
		}
	}
	// Fall back to IP alone (legacy NULL-network or cross-network match).
	var id int64
	err := r.db.QueryRowContext(ctx,
		`SELECT id FROM devices WHERE ip_address = ? LIMIT 1`, ip).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// resolveDeviceUUID returns the stable device_uuid for an IP using the same
// identity rule as resolveDeviceID (network-scoped IP match, then global IP).
// Returns "" when no device matches — the caller writes "" into the satellite
// row and it is healed on the next scan (or by the backfill migration). The
// empty-string sentinel is safe because devices.device_uuid is always populated
// (non-empty) once a row exists — backfillDeviceUUIDs guarantees it.
//
// Results are memoized in r.uuidCache (IP → UUID). UUIDs are stable device
// identity, so the cache is correct across calls; a /24 scan with 50 alive
// hosts previously triggered ~200 DB round-trips here (one per Record* call per
// host). The cache collapses that to ~50 (one per unique IP). (#162)
func (r *SQLiteRepository) resolveDeviceUUID(ctx context.Context, ip string) (string, error) {
	// Fast path: cache hit (includes cached "" for known-absent IPs).
	r.uuidMu.Lock()
	if u, ok := r.uuidCache[ip]; ok {
		r.uuidMu.Unlock()
		return u, nil
	}
	r.uuidMu.Unlock()

	var q string
	var args []any
	if r.networkID.Valid {
		q = `SELECT device_uuid FROM devices WHERE ip_address = ? AND network_id = ? LIMIT 1`
		args = []any{ip, r.networkID.Int64}
	} else {
		q = `SELECT device_uuid FROM devices WHERE ip_address = ? AND (network_id IS NULL OR network_id = (SELECT MIN(network_id) FROM devices WHERE ip_address = ?)) LIMIT 1`
		args = []any{ip, ip}
	}
	var u string
	err := r.db.QueryRowContext(ctx, q, args...).Scan(&u)
	if err == sql.ErrNoRows || err != nil {
		// Fall back to any device with this IP (cross-network / NULL-network).
		if r.networkID.Valid {
			err = r.db.QueryRowContext(ctx,
				`SELECT device_uuid FROM devices WHERE ip_address = ? LIMIT 1`, ip).Scan(&u)
		}
		if err != nil {
			// Do NOT cache the negative result ("") — a device may be created
			// between scan passes (the heal scenario the tests verify), so a
			// stale "" would block the UUID from ever resolving. Only non-empty
			// results are cached (UUIDs are stable once assigned). (#162)
			return "", err
		}
	}
	r.uuidMu.Lock()
	r.uuidCache[ip] = u
	r.uuidMu.Unlock()
	return u, nil
}
