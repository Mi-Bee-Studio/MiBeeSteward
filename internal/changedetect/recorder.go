// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Package changedetect implements the change-detection engine: when a scan
// finds a device new/changed/lost vs the known state, a change event is emitted
// to a ChangeRecorder (which writes change_log + pushes in-process Watcher
// subscribers). This is the "diff + emit" half of the准实时画像 (the snapshot
// storage + lost detection live alongside in the runner + scan_snapshots).
//
// See docs/private/architecture-future.md §8 for the design.
package changedetect

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"mibee-steward/internal/db"
)

// changesTotal is the Prometheus counter for emitted change events, labeled by
// change_type (device_added/changed/lost). Registered once at package init so
// /metrics exposes the change rate (a healthy network sees few changes; a burst
// signals a real topology shift or a scan outage).
var changesTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "mibee_changes_total",
		Help: "Total device change events emitted by the change-detection engine",
	},
	[]string{"type"},
)

func init() {
	prometheus.MustRegister(changesTotal)
}

// ChangeType enumerates the device-level change events. The pattern is
// {entity}_{added|lost|changed|recovered}; service/neighbor variants are
// reserved for later phases.
//
// Event model (v2 — separated liveness from identity):
//   - device_added    — a brand-new device was discovered (identity event)
//   - device_lost     — a known device has been absent from ≥lostThreshold
//     consecutive scans (topology/liveness event; the row is
//     NOT deleted, only status→offline)
//   - device_recovered — a device previously declared lost reappeared in a scan
//     (the symmetric counterpart of device_lost; replaces the
//     old practice of reporting an offline→online flip as a
//     generic device_changed, which buried real changes)
//   - device_changed  — an IDENTITY field of a known device changed
//     (name/type/brand/model/mac/ip). Classification-field
//     drift (open_ports/services/scan_attributes) is recorded
//     in before/after_data for the diff viewer but no longer
//     single-handedly fires device_changed.
//
// Liveness (status online↔offline driven by heartbeat probing) is NOT a change
// event at all — it is the heartbeat service's concern (status badge, offline
// backoff). Conflating liveness with device_changed was the root cause of the
// 70k+ noise-row storm on the test env (a flapping host emitted one
// device_lost + one device_changed per flap cycle).
const (
	ChangeTypeDeviceAdded     = "device_added"
	ChangeTypeDeviceChanged   = "device_changed"
	ChangeTypeDeviceLost      = "device_lost"
	ChangeTypeDeviceRecovered = "device_recovered"
)

// EntityType is always "device" in this phase (service/neighbor reserved).
const EntityTypeDevice = "device"

// Severity ranks a change event for UI triage. The change-history page defaults
// to showing identity-tier events so real adds/removes/identity-changes are
// visible; enrichment-tier drift (port/service/scan-attr wobble) is available
// behind a filter but not in your face.
const (
	SeverityIdentity   = "identity"   // device_added / device_lost / device_recovered / identity-field device_changed
	SeverityLiveness   = "liveness"   // reserved (liveness is heartbeat's job; no events today)
	SeverityEnrichment = "enrichment" // classification-field-only device_changed (rare under the new model)
)

// ChangeEvent is one detected change. Before/After are JSON snapshots of the
// device row (nil for added's before / lost's after). DeviceID is the devices.id
// the change concerns; NetworkID + AgentID carry provenance. Severity is the
// UI-triage tier (identity/liveness/enrichment); callers that omit it get
// SeverityIdentity for the discrete add/lost/recovered events and
// SeverityEnrichment for classification-only device_changed.
type ChangeEvent struct {
	ChangeType string
	EntityType string
	Severity   string // "" → inferred from ChangeType in Record
	DeviceID   int64
	NetworkID  *int64
	AgentID    string
	Before     any // marshalled to before_data JSON; nil for device_added
	After      any // marshalled to after_data JSON; nil for device_lost
}

// ChangeRecorder consumes change events. The runner holds one (injected at
// construction; nil on the agent, which doesn't do center-side change detection).
// Implementations: NoopRecorder (tests/agent), DBRecorder (center: writes
// change_log + pushes Watcher subscribers).
type ChangeRecorder interface {
	Record(ctx context.Context, ev ChangeEvent)
}

// NoopRecorder drops every event. Used by the agent (change detection is a
// center concern) and in tests that don't assert on change_log.
type NoopRecorder struct{}

func (NoopRecorder) Record(context.Context, ChangeEvent) {}

// DeviceSnapshot is the JSON-serializable device view captured for before/after
// diffing. Only the fields that constitute a "change" are tracked (per the
// all-fields decision): identity + classification + scan enrichment. Timestamps
// (last_seen/last_scanned_at/updated_at) are excluded — they change every scan
// and would drown the signal.
type DeviceSnapshot struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	Brand            string `json:"brand"`
	Model            string `json:"model"`
	MacAddress       string `json:"mac_address"`
	IPAddress        string `json:"ip_address"`
	Status           string `json:"status"`
	OpenPorts        string `json:"open_ports"`
	DetectedServices string `json:"detected_services"`
	PrometheusURL    string `json:"prometheus_url"`
	NodeExporterURL  string `json:"node_exporter_url"`
	ScanAttributes   string `json:"scan_attributes"`
}

// SnapshotFromDevice builds a DeviceSnapshot from a sqlc device row (the
// "before" state read during applyDeviceBridge, or the "after" state re-read
// after the upsert). Used for both before_data and after_data.
func SnapshotFromDevice(d db.Device) DeviceSnapshot {
	return DeviceSnapshot{
		Name:             d.Name,
		Type:             d.Type,
		Brand:            d.Brand,
		Model:            d.Model,
		MacAddress:       d.MacAddress,
		IPAddress:        d.IpAddress,
		Status:           d.Status,
		OpenPorts:        d.OpenPorts,
		DetectedServices: d.DetectedServices,
		PrometheusURL:    d.PrometheusUrl,
		NodeExporterURL:  d.NodeExporterUrl,
		ScanAttributes:   d.ScanAttributes,
	}
}

// identityFields are the fields that define a device's IDENTITY — a change to
// any of these is a meaningful device_changed event (e.g. a router swap renamed
// NanoPiR4S → GL-MT3000, or a device's MAC was resolved for the first time).
// These drive the DiffIdentity comparison that gates device_changed emission.
//
// NOTE: type/brand/model are included even though they are scanner-INFERRED
// (and thus somewhat volatile). The evidence-stickiness layer in
// applyDeviceBridge (runner/device_bridge.go) ensures these don't flap
// run-to-run (a protocol-derived type is authoritative and not downgraded to a
// heuristic guess on a later scan where the probe timed out). So once
// stickiness is in place, a type change reaching DiffIdentity is a REAL
// identity change, not scan noise.
var identityFields = []struct {
	name string
	get  func(DeviceSnapshot) string
}{
	{"name", func(s DeviceSnapshot) string { return s.Name }},
	{"type", func(s DeviceSnapshot) string { return s.Type }},
	{"brand", func(s DeviceSnapshot) string { return s.Brand }},
	{"model", func(s DeviceSnapshot) string { return s.Model }},
	{"mac_address", func(s DeviceSnapshot) string { return s.MacAddress }},
	{"ip_address", func(s DeviceSnapshot) string { return s.IPAddress }},
}

// classificationFields are scanner-enrichment fields that wobble run-to-run as
// probe depth/success varies (a port that answered this scan but timed out next
// scan; a service banner re-parsed slightly differently). A change confined to
// these is recorded in before/after_data for the diff viewer but does NOT
// single-handedly fire a device_changed event — it is enrichment-tier drift,
// not an identity change. status is deliberately ABSENT from both lists: it is
// a liveness signal owned by the heartbeat service, not a change event.
var classificationFields = []struct {
	name string
	get  func(DeviceSnapshot) string
}{
	{"open_ports", func(s DeviceSnapshot) string { return s.OpenPorts }},
	{"detected_services", func(s DeviceSnapshot) string { return s.DetectedServices }},
	{"prometheus_url", func(s DeviceSnapshot) string { return s.PrometheusURL }},
	{"node_exporter_url", func(s DeviceSnapshot) string { return s.NodeExporterURL }},
	{"scan_attributes", func(s DeviceSnapshot) string { return normalizeScanAttrs(s.ScanAttributes) }},
}

// DiffIdentity returns the subset of IDENTITY fields that differ between before
// and after, as a map[field]{old, new}. Returns nil when no identity field
// changed — which is the gate for emitting a device_changed event. This is the
// field-by-field comparison that replaces the old all-fields Diff that fired on
// every rescan regardless of whether anything meaningful changed.
//
// status is intentionally excluded: an offline↔online flip is a liveness
// signal (heartbeat's concern), reported via device_lost/device_recovered when
// it crosses the scan-absence threshold, never as device_changed.
func DiffIdentity(before, after DeviceSnapshot) map[string][2]string {
	return diffFields(before, after, identityFields)
}

// DiffClassification returns the subset of classification/enrichment fields
// that differ. Callers use this to populate before/after_data so the diff
// viewer can show what the scanner re-observed, WITHOUT treating it as an
// identity-level change. Returns nil when nothing differs.
func DiffClassification(before, after DeviceSnapshot) map[string][2]string {
	return diffFields(before, after, classificationFields)
}

// diffFields is the shared per-field comparison used by both DiffIdentity and
// DiffClassification.
func diffFields(before, after DeviceSnapshot, fields []struct {
	name string
	get  func(DeviceSnapshot) string
}) map[string][2]string {
	changed := map[string][2]string{}
	for _, f := range fields {
		o, n := f.get(before), f.get(after)
		if o != n {
			changed[f.name] = [2]string{o, n}
		}
	}
	if len(changed) == 0 {
		return nil
	}
	return changed
}

// Diff is retained for backwards compatibility with callers/tests that want
// "anything changed at all" (identity OR classification). It is the union of
// DiffIdentity and DiffClassification. New code should call DiffIdentity (the
// device_changed gate) or DiffClassification (enrichment) directly. status is
// excluded from this union too.
func Diff(before, after DeviceSnapshot) map[string][2]string {
	out := diffFields(before, after, identityFields)
	cls := diffFields(before, after, classificationFields)
	if out == nil && cls != nil {
		out = map[string][2]string{} // nil map needs init before writing
	}
	for k, v := range cls {
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// volatileScanAttrKeys are scan_attributes JSON keys that change every scan by
// nature and must NOT trip a device_changed/classification diff. Two groups:
//
//  1. Timestamps / transient counters (last_scanned_at, last_scan_rtt_ms) — they
//     move every scan by definition. The canonical timestamp lives on the
//     top-level devices.last_scanned_at column; embedding a copy inside
//     scan_attributes once generated 53k bogus device_changed rows in 2 days.
//
//  2. Scanner-inferred identity keys (inferred_type, inferred_type_source,
//     inferred_brand, inferred_description, hostname) — these wobble run-to-run
//     as probe success varies (SNMP present → type from protocol; SNMP timed
//     out → type falls back to a hostname heuristic). The evidence-stickiness
//     layer in applyDeviceBridge makes the PERSISTED device.type/brand
//     authoritative and immune to this wobble, so the duplicate copy inside
//     scan_attributes is redundant for change-detection purposes. The device's
//     actual type/brand/name identity flows through the identityFields
//     comparison (DiffIdentity) on the top-level columns, not via these nested
//     scan_attributes echoes. Stripping them here neutralizes the 81% of
//     device_changed noise that was pure scan_attributes wobble on the test env.
//
// This normalization is a defense-in-depth backstop — the scanner's
// evidence-stickiness layer is the primary fix, but legacy rows / future
// regressions are neutralized here so a Diff can never fire on these keys.
var volatileScanAttrKeys = []string{
	"last_scanned_at", "last_scan_rtt_ms",
	"inferred_type", "inferred_type_source",
	"inferred_brand", "inferred_description", "inferred_location",
	"hostname", // echo of devices.name; identity flows via the name column
	"os",       // SNMP sysDescr-derived; wobbles with probe success (covered by stickiness)
}

// normalizeScanAttrs parses a scan_attributes JSON string, drops the volatile
// keys, and re-marshals with sorted object keys so two snapshots that differ
// ONLY in key order or volatile fields compare equal. Returns the input
// unchanged (not "") when it is not a JSON object (malformed/empty) — those
// cases still surface as a real diff, which is the safe failure mode.
func normalizeScanAttrs(s string) string {
	if s == "" || s[0] != '{' {
		return s
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return s
	}
	for _, k := range volatileScanAttrKeys {
		delete(m, k)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return s
	}
	return string(b)
}

// DBRecorder is the center's ChangeRecorder: writes each event to change_log
// (via sqlc) and fans it out to in-process Watcher subscribers. The runner
// calls Record synchronously per host; writes are best-effort (logged, never
// abort a scan on a change_log failure).
//
// Cooldown dedup: device_changed and device_recovered events for the SAME
// device are suppressed if an event of the same type was emitted within the
// cooldown window (default 15m). This stops a flapping/scanning-rapid host from
// spamming identical changes — the first change in a window is recorded, the
// rest are dropped (the device's current state is already reflected in the
// devices row; change_log is a log of *transitions*, not a heartbeat).
// device_added/device_lost are NEVER throttled — they are discrete, meaningful
// topology events that must always be recorded.
type DBRecorder struct {
	queries       *db.Queries
	watcher       *Watcher
	logger        *slog.Logger
	cooldown      time.Duration // 0 disables dedup
	lastEmittedMu sync.Mutex
	lastEmitted   map[dedupKey]time.Time // (deviceID, changeType) → last emit time
}

type dedupKey struct {
	deviceID int64
	kind     string
}

// NewDBRecorder constructs the center recorder. watcher may be nil (no
// subscriber fan-out); queries must be the center's main DB. cooldown is the
// dedup window for device_changed/device_recovered (pass 0 to disable).
func NewDBRecorder(queries *db.Queries, watcher *Watcher, cooldown time.Duration, logger *slog.Logger) *DBRecorder {
	if logger == nil {
		logger = slog.Default()
	}
	r := &DBRecorder{queries: queries, watcher: watcher, cooldown: cooldown, logger: logger}
	if cooldown > 0 {
		r.lastEmitted = make(map[dedupKey]time.Time)
	}
	return r
}

// Record writes the event to change_log + pushes Watcher subscribers. It infers
// a severity tier when the caller didn't set one, and applies cooldown dedup to
// device_changed/device_recovered.
func (r *DBRecorder) Record(ctx context.Context, ev ChangeEvent) {
	severity := ev.Severity
	if severity == "" {
		severity = severityFor(ev.ChangeType)
	}
	if !r.shouldEmit(ev.DeviceID, ev.ChangeType) {
		// Suppressed by cooldown dedup. The devices row already reflects the
		// current state; change_log records transitions, not every observation.
		return
	}
	changesTotal.WithLabelValues(ev.ChangeType).Inc()
	beforeJSON, _ := marshalSnapshot(ev.Before)
	afterJSON, _ := marshalSnapshot(ev.After)
	now := time.Now().UTC()
	row, err := r.queries.CreateChangeLog(ctx, db.CreateChangeLogParams{
		AgentID:    ptrString(ev.AgentID),
		NetworkID:  ev.NetworkID,
		ChangeType: ev.ChangeType,
		EntityType: ev.EntityType,
		EntityID:   ptrInt64(ev.DeviceID),
		BeforeData: beforeJSON,
		AfterData:  afterJSON,
		DetectedAt: now,
	})
	if err != nil {
		r.logger.Warn("change recorder: write change_log failed", "type", ev.ChangeType, "device_id", ev.DeviceID, "error", err)
		return
	}
	r.markEmitted(ev.DeviceID, ev.ChangeType, now)
	if r.watcher != nil {
		r.watcher.push(row)
	}
}

// shouldEmit applies the cooldown dedup. device_added/device_lost always emit
// (discrete topology events). device_changed/device_recovered emit only if no
// event of the same type for the same device was recorded within the cooldown.
func (r *DBRecorder) shouldEmit(deviceID int64, changeType string) bool {
	if r.cooldown <= 0 {
		return true
	}
	switch changeType {
	case ChangeTypeDeviceChanged, ChangeTypeDeviceRecovered:
		// throttleable
	default:
		return true // device_added/device_lost always record
	}
	r.lastEmittedMu.Lock()
	defer r.lastEmittedMu.Unlock()
	key := dedupKey{deviceID: deviceID, kind: changeType}
	if last, ok := r.lastEmitted[key]; ok {
		if time.Since(last) < r.cooldown {
			return false
		}
	}
	return true
}

// markEmitted records the emit time for cooldown tracking.
func (r *DBRecorder) markEmitted(deviceID int64, changeType string, now time.Time) {
	if r.cooldown <= 0 {
		return
	}
	r.lastEmittedMu.Lock()
	defer r.lastEmittedMu.Unlock()
	r.lastEmitted[dedupKey{deviceID: deviceID, kind: changeType}] = now
}

// severityFor infers the UI-triage tier from the change type when the caller
// didn't set one explicitly.
func severityFor(changeType string) string {
	switch changeType {
	case ChangeTypeDeviceAdded, ChangeTypeDeviceLost, ChangeTypeDeviceRecovered:
		return SeverityIdentity
	default:
		return SeverityEnrichment
	}
}

// marshalSnapshot marshals a snapshot/diff to its JSON string form (nil → NULL).
func marshalSnapshot(v any) (*string, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	s := string(b)
	return &s, nil
}

func ptrString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func ptrInt64(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}

// Watcher is the in-process change-event fan-out (architecture-future.md §8
// Watcher interface). Subscribers receive change_log rows on a buffered channel;
// slow subscribers are dropped (non-blocking) to prevent one laggy consumer
// from stalling the scan pipeline. This is the foundation for a future /watch
// SSE endpoint.
type Watcher struct {
	mu          sync.RWMutex
	subscribers map[chan db.ChangeLog]struct{}
	logger      *slog.Logger
}

// NewWatcher constructs a Watcher.
func NewWatcher(logger *slog.Logger) *Watcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Watcher{subscribers: map[chan db.ChangeLog]struct{}{}, logger: logger}
}

// Subscribe returns a buffered channel of change events. The caller drains it;
// if it fills, events are dropped (with a log) rather than blocking the emitter.
// Unsubscribe via the returned channel.
func (w *Watcher) Subscribe() <-chan db.ChangeLog {
	ch := make(chan db.ChangeLog, 64)
	w.mu.Lock()
	w.subscribers[ch] = struct{}{}
	w.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscription and closes its channel. The argument is the
// receive channel returned by Subscribe; channel identity is compared via the
// any-conversion (a bidirectional chan and its <-chan view of the SAME channel
// compare equal once both are boxed in an interface).
func (w *Watcher) Unsubscribe(ch <-chan db.ChangeLog) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for sub := range w.subscribers {
		if any(sub) == any(ch) {
			delete(w.subscribers, sub)
			close(sub)
			return
		}
	}
}

// push fans a change row to all subscribers (non-blocking).
func (w *Watcher) push(row db.ChangeLog) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for ch := range w.subscribers {
		select {
		case ch <- row:
		default:
			// Subscriber buffer full — drop to avoid blocking the scan. A laggy
			// consumer can re-query change_log; real-time is best-effort here.
			w.logger.Debug("watcher: subscriber full, dropping change event", "change_id", row.ID)
		}
	}
}
