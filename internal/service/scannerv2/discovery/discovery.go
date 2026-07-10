// Package discovery implements the long-running passive host-discovery
// service.
//
// It complements the cron-driven full-subnet scan with a near-zero-traffic
// watcher that spots newly-appeared hosts and feeds them into the runner's
// device bridge (so they get device_added change events + heartbeat seeding)
// without waiting for the next scheduled scan.
//
// The discovery and identification concerns are deliberately decoupled:
//   - discovery (this package): cheap, continuous, mostly passive — answer
//     "did a NEW host show up?" via ARP-table diffs and mDNS/SSDP listening.
//   - identification (the existing scannerv2 probe/classify pipeline): run on
//     demand for a SINGLE newly-discovered IP, not the whole subnet.
//
// Sources emit NewHostEvents into the coordinator, which dedupes against both a
// short memory window (to avoid reprocessing the same burst) and the device DB
// (so only genuinely-unknown hosts trigger the expensive single-IP identify
// scan). All sources share the single coordinator goroutine for serialization,
// so the runner's device-bridge upserts are never concurrent with themselves.
package discovery

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/engine"
	"mibee-steward/internal/service/scannerv2/runner"
)

// NewHostEvent is what each discovery source produces: a host it has just
// noticed that it wants the coordinator to consider. MAC is optional (router
// ARP carries it; an mDNS-only sighting may not). Hints carry source-specific
// clues (e.g. an mDNS _onvif._tcp service → camera hint) the coordinator can
// attach to the synthesized report.
type NewHostEvent struct {
	IP    string
	MAC   string
	Source string
	Hints map[string]string
}

// HostSink is the coordinator's outlet: it hands a synthesized HostReport to
// the runner's device bridge. The runner's ApplyReport satisfies this via a
// thin adapter (the runner lives in a sibling package and uses sql.NullInt64,
// so the adapter keeps this package free of that detail).
type HostSink interface {
	// Apply runs rep through the device bridge (create/update + change detection
	// + heartbeat seeding). Returns whether the host was newly created.
	Apply(ctx context.Context, rep scannerv2.HostReport) (isNew bool)
}

// Identifier runs the full single-IP identification pipeline (the existing
// scannerv2 probe/classify/cascade set) against one IP and returns the
// resulting HostReport. The *engine.Engine satisfies this directly.
type Identifier interface {
	Identify(ctx context.Context, ip string) (scannerv2.HostReport, bool)
}

// engineIdentifier adapts *engine.Engine to the Identifier interface. It
// returns (report, true) when the host was alive and produced a report.
type engineIdentifier struct {
	engine *engine.Engine
}

func (e *engineIdentifier) Identify(ctx context.Context, ip string) (scannerv2.HostReport, bool) {
	if e.engine == nil {
		return scannerv2.HostReport{}, false
	}
	reports, err := e.engine.ScanTargets(ctx, ip, false)
	if err != nil || len(reports) == 0 {
		return scannerv2.HostReport{}, false
	}
	rep := reports[0]
	return rep, rep.Alive
}

// Config configures the coordinator. Source-level enable flags live on each
// source's own config; this is the cross-cutting behavior.
type Config struct {
	// Interval is the poll cadence for the ARP-based sources (router_arp,
	// arp_cache). The multicast source ignores this (it listens continuously).
	Interval time.Duration
	// TriggerIdentify, when true, runs a single-IP full identification scan on
	// each genuinely-new host so it gets a type + services immediately. When
	// false, the host is recorded with inferred_type="unknown" + a bare ICMP
	// heartbeat.
	TriggerIdentify bool
}

// Service is the passive-discovery coordinator. It owns the sources and the
// single consumer goroutine that processes NewHostEvents.
type Service struct {
	cfg    Config
	sink   HostSink
	ident  Identifier
	nid    sql.NullInt64
	db     *sql.DB // for the "is this host already known?" pre-check
	logger *slog.Logger

	events chan NewHostEvent
	cancel context.CancelFunc
	done   chan struct{}

	// recent is a short memory window keyed by IP: hosts seen by the coordinator
	// within dedupTTL are not reprocessed even if another source reports them
	// again in the same burst. This is independent of the DB pre-check: the DB
	// check answers "is the host new to the system?", this answers "have I
	// already handled this IP in the last few minutes?".
	recent   map[string]time.Time
	recentMu sync.Mutex
}

const dedupTTL = 5 * time.Minute

// New constructs the coordinator. dbConn is used for the known-host pre-check
// (SELECT from devices); networkID tags synthesized reports with the origin
// network (0/NULL for the legacy single-instance path — same convention as
// runner.New). ident may be nil (TriggerIdentify is then effectively forced off).
func New(cfg Config, sink HostSink, ident Identifier, dbConn *sql.DB, networkID int64, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	var nid sql.NullInt64
	if networkID > 0 {
		nid = sql.NullInt64{Int64: networkID, Valid: true}
	}
	return &Service{
		cfg:    cfg,
		sink:   sink,
		ident:  ident,
		nid:    nid,
		db:     dbConn,
		logger: logger,
		events: make(chan NewHostEvent, 256),
		recent: make(map[string]time.Time),
	}
}

// Start launches the coordinator's consumer goroutine. It is the caller's
// responsibility to also start each source (sources are returned/constructed
// separately so callers can decide which to run). Idempotent.
func (s *Service) Start(ctx context.Context) {
	if s.cancel != nil {
		return // already started
	}
	ctx, s.cancel = context.WithCancel(ctx)
	s.done = make(chan struct{})
	go s.loop(ctx)
}

// Stop signals the consumer goroutine to exit and blocks until it has. Safe
// to call when never started (no-op). Must be called before db.Close().
func (s *Service) Stop() {
	if s.cancel == nil {
		return
	}
	s.cancel()
	if s.done != nil {
		<-s.done
	}
	s.cancel = nil
	s.done = nil
}

// Emit pushes a NewHostEvent to the coordinator. Non-blocking: a full channel
// drops the event with a debug log (a transient burst shouldn't block a
// source's read loop).
func (s *Service) Emit(ev NewHostEvent) {
	select {
	case s.events <- ev:
	default:
		s.logger.Debug("discovery: event dropped (channel full)", "ip", ev.IP, "source", ev.Source)
	}
}

// loop is the single consumer. Serializing all source events here means the
// runner's device-bridge upserts are never concurrent with each other.
func (s *Service) loop(ctx context.Context) {
	defer close(s.done)
	// Periodically sweep the recent-memory window so it doesn't grow unbounded.
	sweep := time.NewTicker(dedupTTL)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-s.events:
			s.handle(ctx, ev)
		case <-sweep.C:
			s.sweepRecent()
		}
	}
}

// handle processes one event: dedup against recent memory + the device DB, then
// either run a single-IP identify scan or synthesize a minimal report, and feed
// it to the sink.
func (s *Service) handle(ctx context.Context, ev NewHostEvent) {
	if ev.IP == "" {
		return
	}
	if s.seenRecently(ev.IP) {
		return
	}
	// Mark as recently-handled regardless of outcome so a repeated burst doesn't
	// re-enter; a genuine re-appearance after dedupTTL will be re-evaluated.
	s.markSeen(ev.IP)

	known, err := s.isKnownHost(ctx, ev.IP, ev.MAC)
	if err != nil {
		// On query error, assume known to avoid a noisy identify storm — the next
		// scheduled full scan will reconcile. Log for visibility.
		s.logger.Warn("discovery: known-host pre-check failed; skipping", "ip", ev.IP, "error", err)
		return
	}
	if known {
		return // already in the device DB — not new
	}

	s.logger.Info("discovery: new host found", "ip", ev.IP, "mac", ev.MAC, "source", ev.Source)

	var rep scannerv2.HostReport
	if s.cfg.TriggerIdentify && s.ident != nil {
		if r, alive := s.ident.Identify(ctx, ev.IP); alive {
			rep = r
			// If the source carried a MAC the identify scan might not have
			// (cross-subnet), fold it in so the bridge's MAC-primary identity
			// matches across roamers.
			rep = foldMAC(rep, ev.MAC)
			rep = foldHints(rep, ev.Hints)
		} else {
			// Host was ARP-seen but didn't respond to the active probes (firewalled
			// ICMP, scan raced ahead of boot). Record it minimally so it's at least
			// tracked, rather than silently dropping the sighting.
			rep = synthesizeReport(ev)
		}
	} else {
		rep = synthesizeReport(ev)
	}

	if isNew := s.sink.Apply(ctx, rep); isNew {
		s.logger.Info("discovery: device recorded", "ip", ev.IP, "source", ev.Source)
	}
}

// isKnownHost reports whether the host is already tracked. The lookup mirrors
// applyDeviceBridge's MAC-primary identity rule so the two stay in agreement:
//
//  1. When a MAC is known, match it GLOBALLY (across all networks/IPs) first.
//     This is the critical case for roaming/DHCP-churned hosts: a device that
//     was recorded as .143 may next appear in the ARP cache as .144 (same MAC,
//     new lease). Without this MAC check, the IP-only lookup below would miss
//     it, the coordinator would treat it as "new", and trigger an expensive
//     full single-IP identify scan — every poll cycle, forever. On a
//     memory-constrained host that scan loop can become a stability hazard.
//  2. Fall back to (ip, network_id), the identity rule for MAC-less sightings.
func (s *Service) isKnownHost(ctx context.Context, ip, mac string) (bool, error) {
	if s.db == nil {
		return false, nil
	}
	// 1. MAC-primary: a known MAC is a known host regardless of which IP it
	//    currently holds. (Empty MAC → skip, fall through to IP lookup.)
	if mac != "" {
		var macID int64
		err := s.db.QueryRowContext(ctx,
			`SELECT id FROM devices WHERE mac_address = ? LIMIT 1`, mac).Scan(&macID)
		if err == nil {
			return true, nil
		}
		if err != sql.ErrNoRows {
			return false, err
		}
	}
	// 2. IP + network_id fallback.
	var id int64
	var err error
	if s.nid.Valid {
		err = s.db.QueryRowContext(ctx,
			`SELECT id FROM devices WHERE ip_address = ? AND network_id = ? LIMIT 1`,
			ip, s.nid.Int64).Scan(&id)
	} else {
		err = s.db.QueryRowContext(ctx,
			`SELECT id FROM devices WHERE ip_address = ? AND network_id IS NULL LIMIT 1`,
			ip).Scan(&id)
	}
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *Service) seenRecently(ip string) bool {
	s.recentMu.Lock()
	defer s.recentMu.Unlock()
	_, ok := s.recent[ip]
	return ok
}

func (s *Service) markSeen(ip string) {
	s.recentMu.Lock()
	s.recent[ip] = time.Now()
	s.recentMu.Unlock()
}

func (s *Service) sweepRecent() {
	cutoff := time.Now().Add(-dedupTTL)
	s.recentMu.Lock()
	for ip, t := range s.recent {
		if t.Before(cutoff) {
			delete(s.recent, ip)
		}
	}
	s.recentMu.Unlock()
}

// synthesizeReport builds a minimal HostReport for a host that was seen by a
// passive source but not (or not yet) identified. It carries the MAC as evidence
// (so the bridge's MAC-primary identity logic still works for roamers) and an
// "unknown" type so the device is tracked even when the identify scan is
// disabled or the host is unresponsive to active probes.
func synthesizeReport(ev NewHostEvent) scannerv2.HostReport {
	rep := scannerv2.HostReport{
		IP:    ev.IP,
		Alive: true,
		Device: scannerv2.DeviceRef{
			IP:     ev.IP,
			Fields: map[string]string{"inferred_type": "unknown"},
		},
	}
	if ev.MAC != "" {
		rep.Device.Fields["mac"] = ev.MAC
		rep.Evidence = append(rep.Evidence, scannerv2.Evidence{
			Source:     "discovery:" + ev.Source,
			Kind:       "mac",
			IP:         ev.IP,
			Protocol:   "arp",
			RawData:    map[string]string{"mac": ev.MAC},
			Confidence: 0.8,
			ObservedAt: time.Now(),
		})
	}
	// Fold source hints (e.g. _onvif._tcp → camera) into device fields.
	for k, v := range ev.Hints {
		rep.Device.Fields[k] = v
	}
	return rep
}

// foldMAC ensures the report carries the source-observed MAC when the identify
// scan couldn't resolve one (typical for cross-subnet passive sightings).
func foldMAC(rep scannerv2.HostReport, mac string) scannerv2.HostReport {
	if mac == "" {
		return rep
	}
	if rep.Device.Fields == nil {
		rep.Device.Fields = map[string]string{}
	}
	if _, ok := rep.Device.Fields["mac"]; !ok {
		rep.Device.Fields["mac"] = mac
		rep.Evidence = append(rep.Evidence, scannerv2.Evidence{
			Source:     "discovery:router_arp",
			Kind:       "mac",
			IP:         rep.IP,
			Protocol:   "arp",
			RawData:    map[string]string{"mac": mac},
			Confidence: 0.8,
			ObservedAt: time.Now(),
		})
	}
	return rep
}

// foldHints copies passive-source hints onto an identified report without
// clobbering fields the identify scan populated (e.g. don't overwrite a real
// inferred_type with a weak mDNS hint).
func foldHints(rep scannerv2.HostReport, hints map[string]string) scannerv2.HostReport {
	if len(hints) == 0 {
		return rep
	}
	if rep.Device.Fields == nil {
		rep.Device.Fields = map[string]string{}
	}
	for k, v := range hints {
		if _, exists := rep.Device.Fields[k]; !exists {
			rep.Device.Fields[k] = v
		}
	}
	return rep
}

// SinkAdapter adapts a *runner.Runner to the HostSink interface, binding the
// network identity and agent provenance into each Apply call.
type SinkAdapter struct {
	Runner  *runner.Runner
	AgentID string
}

// Apply hands rep to the runner's device bridge.
func (a SinkAdapter) Apply(ctx context.Context, rep scannerv2.HostReport) bool {
	isNew, _, _ := a.Runner.ApplyReport(ctx, rep, a.Runner.NetworkID(), a.AgentID)
	return isNew
}

// IdentifierAdapter adapts *engine.Engine to the Identifier interface.
func IdentifierAdapter(e *engine.Engine) Identifier { return &engineIdentifier{engine: e} }
