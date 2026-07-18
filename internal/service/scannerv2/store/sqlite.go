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
	"time"

	"mibee-steward/internal/domain"

	"mibee-steward/internal/service/scannerv2"
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
	}
}

// Compile-time interface check.
var _ scannerv2.Repository = (*SQLiteRepository)(nil)

// RecordEvidence inserts raw evidence rows. Sampling: when persistRawEvidence
// is false, the method is a no-op. Batches inserts in a single tx.
func (r *SQLiteRepository) RecordEvidence(ctx context.Context, evs []scannerv2.Evidence) error {
	if !r.persistRawEvidence || len(evs) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO service_evidence (ip, source, kind, port, protocol, raw_data, confidence, observed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
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
		if _, err := stmt.ExecContext(ctx, e.IP, e.Source, e.Kind, e.Port, e.Protocol, string(raw), e.Confidence, ts.UTC()); err != nil {
			r.logger.Debug("insert evidence row failed", "error", err)
		}
	}
	return tx.Commit()
}

// RecordServices replaces the host's service-identity set atomically.
func (r *SQLiteRepository) RecordServices(ctx context.Context, ip string, services []scannerv2.ServiceIdentity) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, `DELETE FROM host_services WHERE ip = ?`, ip); err != nil {
		return err
	}
	if len(services) == 0 {
		return tx.Commit()
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO host_services (ip, service, port, protocol, confidence, metadata, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
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

	now := time.Now().UTC()
	for _, s := range merged {
		meta, err := json.Marshal(s.Metadata)
		if err != nil {
			meta = []byte("{}")
		}
		if _, err := stmt.ExecContext(ctx, ip, s.Service, s.Port, s.Protocol, s.Confidence, string(meta), now); err != nil {
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
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	// Collect the distinct ports in this batch; delete prior rows for each.
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
			ip, port, cert_index,
			subject_cn, subject_org, subject, issuer_cn, issuer_org, issuer,
			san_dns, san_ip, san_email, serial,
			not_before, not_after,
			sig_algorithm, key_algorithm, key_bits, is_ca, self_signed,
			fingerprint_sha256, pem,
			tls_version, cipher_suite, trusted, error, updated_at
		) VALUES (?, ?, ?,  ?, ?, ?, ?, ?, ?,  ?, ?, ?, ?,  ?, ?,  ?, ?, ?, ?, ?,  ?, ?,  ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().UTC()
	for _, c := range certs {
		if _, err := stmt.ExecContext(ctx,
			ip, c.Port, c.CertIndex,
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

// RecordDevice upserts device fields discovered by the pipeline. The v2 engine
// only enriches; it does not create device identities from scratch (the legacy
// add-devices flow or manual creation does). So this updates existing rows
// matched by ip_address; if none match, it inserts a minimal row.
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
	// Minimal scan_attributes built from the DeviceRef Fields. The runner's
	// device_bridge.go produces the full ScanAttributes (with OpenPorts/
	// DetectedServices/SNMP structured sub-objects); this store path runs
	// in parallel and carries the same key set so the two writers agree on
	// the JSON shape. The unknown/extra keys land under "extras".
	scanAttrs := buildStoreScanAttributes(d, extra, openPorts, detectedServices, promURL, neURL)
	scanAttrsJSON, _ := domain.MarshalScanAttributes(scanAttrs)

	// MAC-primary identity: when a MAC is known, match across ALL networks so a
	// device that roams between subnets (or was discovered by another instance)
	// stays a single asset. Without a MAC, fall back to (ip, network_id): same
	// IP on two different networks is two distinct devices.
	mac := NormalizeMAC(extra["mac"])

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var existingID int64
	switch {
	case mac != "":
		// MAC present → global identity. A device discovered on LAN-A and LAN-B
		// resolves to the same row. (idx_devices_mac_address backs this lookup.)
		err = tx.QueryRowContext(ctx,
			`SELECT id FROM devices WHERE mac_address = ? LIMIT 1`, mac).Scan(&existingID)
		// Fall back to (ip, network_id) when the MAC lookup misses: the device
		// may have been first seen WITHOUT a MAC (ARP hadn't resolved yet) and
		// only picked one up on this scan. Matching it back avoids creating a
		// second row — we want to fill the existing row's mac_address instead.
		if err == sql.ErrNoRows {
			if r.networkID.Valid {
				err = tx.QueryRowContext(ctx,
					`SELECT id FROM devices WHERE ip_address = ? AND network_id = ? AND mac_address = '' LIMIT 1`,
					ip, r.networkID.Int64).Scan(&existingID)
			} else {
				err = tx.QueryRowContext(ctx,
					`SELECT id FROM devices WHERE ip_address = ? AND network_id IS NULL AND mac_address = '' LIMIT 1`,
					ip).Scan(&existingID)
			}
		}
	default:
		// No MAC → identity is (ip, network_id). On the legacy single-instance
		// path network_id is NULL, and SQLite treats each NULL as distinct in a
		// UNIQUE index, so the first NULL-network row for an IP is matched here
		// via the `IS NULL` predicate. With a resolved network_id it partitions.
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
	now := time.Now().UTC()

	name := d.Name
	devType := d.Type
	brand := d.Brand
	model := d.Model
	if name == "" {
		name = ip // default name to IP if unknown
	}
	if devType == "" {
		devType = "other"
	}

	switch err {
	case sql.ErrNoRows:
		// Insert a minimal device row, tagged scan_source='scanner_v2' and
		// stamped with this repository's network_id (origin) + MAC (when known).
		_, err = tx.ExecContext(ctx, `
			INSERT INTO devices (name, type, brand, model, ip_address, mac_address,
			                     status, scan_source,
			                     open_ports, detected_services, prometheus_url, node_exporter_url,
			                     scan_attributes, network_id, first_seen, last_seen,
			                     last_scanned_at, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?,
			        'unknown', 'scanner_v2',
			        ?, ?, ?, ?,
			        ?, ?, ?, ?,
			        ?, ?, ?)`,
			name, devType, brand, model, ip, mac,
			openPorts, detectedServices, promURL, neURL,
			string(scanAttrsJSON), r.networkID, now, now,
			now, now, now)
		if err != nil {
			r.logger.Warn("insert device failed", "ip", ip, "mac", mac, "error", err)
		}
	case nil:
		// Update existing device: only touch v2-managed columns. Refresh MAC,
		// network_id, ip (a re-scan may have resolved a previously-empty MAC or
		// seen the asset on a different IP), and online-freshness timestamps.
		_, err = tx.ExecContext(ctx, `
				UPDATE devices SET
				    brand = CASE WHEN ? != '' THEN ? ELSE brand END,
				    model = CASE WHEN ? != '' THEN ? ELSE model END,
				    type = CASE WHEN ? != '' THEN ? ELSE type END,
				    mac_address = CASE WHEN ? != '' THEN ? ELSE mac_address END,
				    ip_address = CASE WHEN ip_address = '' THEN ? ELSE ip_address END,
				    open_ports = ?,
				    detected_services = ?,
				    prometheus_url = ?,
				    node_exporter_url = ?,
				    scan_attributes = ?,
				    last_seen = COALESCE(last_seen, ?),
				    last_scanned_at = ?,
				    updated_at = ?
				WHERE id = ?`,
			brand, brand, model, model, devType, devType,
			mac, mac, ip,
			openPorts, detectedServices, promURL, neURL, string(scanAttrsJSON),
			now, now, now, existingID)
		if err != nil {
			r.logger.Warn("update device failed", "ip", ip, "mac", mac, "error", err)
		}
	default:
		r.logger.Warn("lookup device failed", "ip", ip, "mac", mac, "error", err)
	}

	return tx.Commit()
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

	now := time.Now().UTC()
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
	devType := fields["type"]
	name := fields["hostname"]
	if name == "" {
		name = fields["sys_name"]
	}

	// Remaining unknown keys go into scan_attributes.extras.
	unknown := make(map[string]string)
	known := map[string]bool{"vendor": true, "model": true, "type": true, "hostname": true, "sys_name": true}
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

	now := time.Now().UTC()
	_, err = r.db.ExecContext(ctx, `
		UPDATE devices SET
		    brand = CASE WHEN ? != '' THEN ? ELSE brand END,
		    model = CASE WHEN ? != '' THEN ? ELSE model END,
		    type = CASE WHEN ? != '' THEN ? ELSE type END,
		    name = CASE WHEN ? != '' THEN ? ELSE name END,
		    scan_attributes = ?,
		    updated_at = ?
		WHERE id = ?`,
		vendor, vendor, model, model, devType, devType, name, name,
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
