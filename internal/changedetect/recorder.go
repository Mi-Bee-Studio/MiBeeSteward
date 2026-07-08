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

	"mibee-steward/internal/db"
)

// ChangeType enumerates the device-level change events. The pattern is
// {entity}_{added|lost|changed}; service/neighbor variants are reserved for
// later phases.
const (
	ChangeTypeDeviceAdded   = "device_added"
	ChangeTypeDeviceChanged = "device_changed"
	ChangeTypeDeviceLost    = "device_lost"
)

// EntityType is always "device" in this phase (service/neighbor reserved).
const EntityTypeDevice = "device"

// ChangeEvent is one detected change. Before/After are JSON snapshots of the
// device row (nil for added's before / lost's after). DeviceID is the devices.id
// the change concerns; NetworkID + AgentID carry provenance.
type ChangeEvent struct {
	ChangeType string
	EntityType string
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

// Diff returns the subset of fields that differ between before and after, as a
// map[field]{old, new} suitable for after_data enrichment. Returns nil when
// nothing differs (no change). This is the field-by-field comparison that
// replaces the old "wasUpdated is always true" heuristic.
func Diff(before, after DeviceSnapshot) map[string][2]string {
	type field struct {
		name string
		get  func(DeviceSnapshot) string
	}
	fields := []field{
		{"name", func(s DeviceSnapshot) string { return s.Name }},
		{"type", func(s DeviceSnapshot) string { return s.Type }},
		{"brand", func(s DeviceSnapshot) string { return s.Brand }},
		{"model", func(s DeviceSnapshot) string { return s.Model }},
		{"mac_address", func(s DeviceSnapshot) string { return s.MacAddress }},
		{"ip_address", func(s DeviceSnapshot) string { return s.IPAddress }},
		{"status", func(s DeviceSnapshot) string { return s.Status }},
		{"open_ports", func(s DeviceSnapshot) string { return s.OpenPorts }},
		{"detected_services", func(s DeviceSnapshot) string { return s.DetectedServices }},
		{"prometheus_url", func(s DeviceSnapshot) string { return s.PrometheusURL }},
		{"node_exporter_url", func(s DeviceSnapshot) string { return s.NodeExporterURL }},
		{"scan_attributes", func(s DeviceSnapshot) string { return s.ScanAttributes }},
	}
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

// DBRecorder is the center's ChangeRecorder: writes each event to change_log
// (via sqlc) and fans it out to in-process Watcher subscribers. The runner
// calls Record synchronously per host; writes are best-effort (logged, never
// abort a scan on a change_log failure).
type DBRecorder struct {
	queries *db.Queries
	watcher *Watcher
	logger  *slog.Logger
}

// NewDBRecorder constructs the center recorder. watcher may be nil (no
// subscriber fan-out); queries must be the center's main DB.
func NewDBRecorder(queries *db.Queries, watcher *Watcher, logger *slog.Logger) *DBRecorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &DBRecorder{queries: queries, watcher: watcher, logger: logger}
}

// Record writes the event to change_log + pushes Watcher subscribers.
func (r *DBRecorder) Record(ctx context.Context, ev ChangeEvent) {
	beforeJSON, _ := marshalSnapshot(ev.Before)
	afterJSON, _ := marshalSnapshot(ev.After)
	now := time.Now().UTC()
	row, err := r.queries.CreateChangeLog(ctx, db.CreateChangeLogParams{
		AgentID:     ptrString(ev.AgentID),
		NetworkID:   ev.NetworkID,
		ChangeType:  ev.ChangeType,
		EntityType:  ev.EntityType,
		EntityID:    ptrInt64(ev.DeviceID),
		BeforeData:  beforeJSON,
		AfterData:   afterJSON,
		DetectedAt:  now,
	})
	if err != nil {
		r.logger.Warn("change recorder: write change_log failed", "type", ev.ChangeType, "device_id", ev.DeviceID, "error", err)
		return
	}
	if r.watcher != nil {
		r.watcher.push(row)
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
