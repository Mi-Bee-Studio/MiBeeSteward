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
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// SQLiteRepository implements scannerv2.Repository against a *sql.DB.
//
// persistRawEvidence gates writing to service_evidence (off by default to
// avoid storage bloat — see config scanner.persist_raw_evidence).
type SQLiteRepository struct {
	db                  *sql.DB
	logger              *slog.Logger
	persistRawEvidence  bool
	defaultHBInterval   int // seconds, 0 → leave config default
	defaultHBTimeout    int // seconds
	defaultSNMPCommunity string
	defaultSNMPOID      string
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
}

// NewSQLiteRepository constructs the repository. db must already have the
// v2 tables (service_evidence, host_services) — main.go applies schema.sql on
// startup, so this holds for the production path. For tests, ensure schema is
// applied to the in-memory DB.
func NewSQLiteRepository(db *sql.DB, opts Options, logger *slog.Logger) *SQLiteRepository {
	if logger == nil {
		logger = slog.Default()
	}
	return &SQLiteRepository{
		db:                   db,
		logger:               logger,
		persistRawEvidence:   opts.PersistRawEvidence,
		defaultHBInterval:    opts.DefaultHeartbeatInterval,
		defaultHBTimeout:     opts.DefaultHeartbeatTimeout,
		defaultSNMPCommunity: opts.DefaultSNMPCommunity,
		defaultSNMPOID:       opts.DefaultSNMPOID,
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

	now := time.Now().UTC()
	for _, s := range services {
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

// RecordDevice upserts device fields discovered by the pipeline. The v2 engine
// only enriches; it does not create device identities from scratch (the legacy
// add-devices flow or manual creation does). So this updates existing rows
// matched by ip_address; if none match, it inserts a minimal row.
func (r *SQLiteRepository) RecordDevice(ctx context.Context, ip string, d scannerv2.DeviceRef) error {
	// The devices table has many columns; v2 touches a known subset. Unknown
	// Fields keys are serialized into prometheus_labels as a JSON extension to
	// avoid schema churn for experimental attributes. Stable keys map to
	// dedicated columns.
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
	extraJSON, _ := json.Marshal(extra)

	// Upsert by ip_address. INSERT ... ON CONFLICT requires a unique index on
	// ip_address, which the existing schema does NOT guarantee. Use a manual
	// check-then-insert/update inside a tx for safety.
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var existingID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM devices WHERE ip_address = ? LIMIT 1`, ip).Scan(&existingID)
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

	if err == sql.ErrNoRows {
		// Insert a minimal device row, tagged scan_source='scanner_v2'.
		_, err = tx.ExecContext(ctx, `
			INSERT INTO devices (name, type, brand, model, ip_address, status, scan_source,
			                     open_ports, detected_services, prometheus_url, node_exporter_url,
			                     prometheus_labels, last_scanned_at, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, 'unknown', 'scanner_v2', ?, ?, ?, ?, ?, ?, ?, ?)`,
			name, devType, brand, model, ip, openPorts, detectedServices, promURL, neURL,
			string(extraJSON), now, now, now)
			if err != nil {
				r.logger.Warn("insert device failed", "ip", ip, "error", err)
			}
		} else if err == nil {
			// Update existing device: only touch v2-managed columns.
			_, err = tx.ExecContext(ctx, `
				UPDATE devices SET
				    brand = CASE WHEN ? != '' THEN ? ELSE brand END,
				    model = CASE WHEN ? != '' THEN ? ELSE model END,
				    type = CASE WHEN ? != '' THEN ? ELSE type END,
				    open_ports = ?,
				    detected_services = ?,
				    prometheus_url = ?,
				    node_exporter_url = ?,
				    prometheus_labels = ?,
				    last_scanned_at = ?,
				    updated_at = ?
				WHERE id = ?`,
				brand, brand, model, model, devType, devType,
				openPorts, detectedServices, promURL, neURL, string(extraJSON), now, now, existingID)
			if err != nil {
				r.logger.Warn("update device failed", "ip", ip, "error", err)
			}
		} else {
			r.logger.Warn("lookup device failed", "ip", ip, "error", err)
		}

	return tx.Commit()
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
