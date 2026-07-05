package scannerv2

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// HostReport is the aggregated result of scanning one IP through the pipeline.
// The orchestrator returns one per scanned IP. The persistence layer (Phase 1)
// consumes it; the API handler translates it into domain.ScanResponse.
type HostReport struct {
	IP        string
	Alive     bool
	RTTMs     int64
	Evidence  []Evidence
	Services  []ServiceIdentity
	Heartbeats []HeartbeatSpec
	// Device is the enriched device view after all handlers ran.
	Device DeviceRef
	// Collected is the per-service deep-collection results, keyed by service.
	// Useful for the API response and for re-hydration in tests.
	Collected map[string]CollectedData
}

// OrchestratorConfig tunes orchestrator behavior.
type OrchestratorConfig struct {
	// MaxConcurrentHosts caps parallel per-host scans (default 50).
	MaxConcurrentHosts int
	// MaxCascadeDepth caps handler→handler trigger chain depth to break
	// cycles (default 5). Depth 0 = no cascade.
	MaxCascadeDepth int
	// PerHostTimeout bounds a single host's full pipeline run (default 30s).
	// In fast-scan mode a shorter timeout is applied per host.
	PerHostTimeout time.Duration
	// FastScan, when true, restricts probes to fingerprint ports only and
	// applies a tighter per-host timeout.
	FastScan bool
}

func (c *OrchestratorConfig) applyDefaults() {
	if c.MaxConcurrentHosts <= 0 {
		c.MaxConcurrentHosts = 50
	}
	if c.MaxCascadeDepth <= 0 {
		c.MaxCascadeDepth = 5
	}
	if c.PerHostTimeout <= 0 {
		c.PerHostTimeout = 30 * time.Second
	}
}

// Orchestrator is the ⑤ pipeline driver. It is constructed with a Registry
// (the registered probes/classifiers/handlers) and a Persistence repository
// (Phase 1; nil allowed in tests — persistence is best-effort).
//
// Run flow per host:
//  1. gather:    run every ProbeSource in parallel, merge Evidence
//  2. persist ①: record evidence (if repo configured & enabled)
//  3. classify:  run every Classifier over the evidence, fuse into Services
//  4. persist ②: record service identities
//  5. dispatch:  for each service with a handler, Collect → EnrichDevice →
//     GenerateHeartbeat, following Triggers up to MaxCascadeDepth
//  6. persist ③: record heartbeats + enriched device
type Orchestrator struct {
	reg    *Registry
	repo   Repository // may be nil (no persistence)
	cfg    OrchestratorConfig
	// cfgMu guards the mutable tuning fields (PerHostTimeout, MaxConcurrentHosts)
	// which SetTimeouts writes from one goroutine (the task runner / sync-scan
	// handler) while Run/ScanTargets read them from many. The rest of cfg is
	// immutable after construction.
	cfgMu  sync.RWMutex
	logger *slog.Logger
}

// NewOrchestrator constructs an orchestrator. repo may be nil to disable
// persistence (used in unit tests). logger defaults to slog.Default if nil.
func NewOrchestrator(reg *Registry, repo Repository, cfg OrchestratorConfig, logger *slog.Logger) *Orchestrator {
	cfg.applyDefaults()
	if logger == nil {
		logger = slog.Default()
	}
	return &Orchestrator{reg: reg, repo: repo, cfg: cfg, logger: logger}
}

// MaxConcurrentHosts exposes the configured per-scan concurrency (read-only).
func (o *Orchestrator) MaxConcurrentHosts() int {
	o.cfgMu.RLock()
	defer o.cfgMu.RUnlock()
	return o.cfg.MaxConcurrentHosts
}

// PerHostTimeout exposes the configured per-host timeout (read-only).
func (o *Orchestrator) PerHostTimeout() time.Duration {
	o.cfgMu.RLock()
	defer o.cfgMu.RUnlock()
	return o.cfg.PerHostTimeout
}

// SetTimeouts reconfigures the per-host timeout and concurrency at runtime.
// Used by the task runner to apply per-task tuning between scans. Safe for
// concurrent callers: it takes the cfg write lock, and readers (MaxConcurrentHosts /
// PerHostTimeout / ScanTargets) take the read lock.
func (o *Orchestrator) SetTimeouts(perHost time.Duration, concurrentHosts int) {
	o.cfgMu.Lock()
	defer o.cfgMu.Unlock()
	o.cfg.applyDefaults() // keep floors
	if perHost > 0 {
		o.cfg.PerHostTimeout = perHost
	}
	if concurrentHosts > 0 {
		o.cfg.MaxConcurrentHosts = concurrentHosts
	}
}

// Run scans a single IP and returns its HostReport. It is the per-host entry
// point; ScanTargets fans out across IPs using Run.
func (o *Orchestrator) Run(ctx context.Context, ip string, hint ProbeHint) HostReport {
	report := HostReport{IP: ip, Collected: make(map[string]CollectedData)}

	// ① gather: run every probe in parallel.
	evidence := o.gather(ctx, ip, hint)
	report.Evidence = evidence
	// Liveness heuristic: a host with at least one non-icmp evidence OR an
	// explicit port_open evidence is alive. (ICMP liveness is set by the icmp
	// probe emitting a port_open/echo evidence — see probe/icmp.go in Phase 2.)
	report.Alive = len(evidence) > 0

	// ① persist raw evidence (best-effort; see Phase 1).
	if o.repo != nil {
		if err := o.repo.RecordEvidence(ctx, evidence); err != nil {
			o.logger.Debug("record evidence failed", "ip", ip, "error", err)
		}
	}

	if !report.Alive {
		return report
	}

	// ② classify.
	var services []ServiceIdentity
	for _, c := range o.reg.Classifiers() {
		services = append(services, c.Classify(evidence)...)
	}
	report.Services = services

	// ② persist service identities.
	if o.repo != nil && len(services) > 0 {
		if err := o.repo.RecordServices(ctx, ip, services); err != nil {
			o.logger.Debug("record services failed", "ip", ip, "error", err)
		}
	}

	// ③ dispatch handlers (with cascade).
	o.dispatch(ctx, &report, hint)

	return report
}

// gather runs every registered ProbeSource in parallel and merges their
// evidence. Per-probe errors are logged and do not abort the gather (a failing
// probe simply contributes no evidence).
func (o *Orchestrator) gather(ctx context.Context, ip string, hint ProbeHint) []Evidence {
	probes := o.reg.Probes()
	type probeResult struct {
		ev  []Evidence
		err error
	}
	results := make([]probeResult, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func(idx int, src ProbeSource) {
			defer wg.Done()
			ev, err := src.Probe(ctx, ip, hint)
			results[idx] = probeResult{ev: ev, err: err}
			if err != nil {
				o.logger.Debug("probe returned error", "source", src.Name(), "ip", ip, "error", err)
			}
		}(i, p)
	}
	wg.Wait()

	var merged []Evidence
	for _, r := range results {
		merged = append(merged, r.ev...)
	}
	return merged
}

// dispatch invokes the handler for each identified service, follows cascade
// triggers up to MaxCascadeDepth, and accumulates heartbeats + collected data +
// device enrichment into the report. Cycle-safe via a visited set keyed by
// service@port.
func (o *Orchestrator) dispatch(ctx context.Context, report *HostReport, hint ProbeHint) {
	// Seed device ref for handlers to mutate.
	if report.Device.IP == "" {
		report.Device = DeviceRef{IP: report.IP, Fields: map[string]string{}}
	}

	type pending struct {
		svc     ServiceIdentity
		context map[string]string
		depth   int
	}
	visited := make(map[string]bool)
	var queue []pending
	for _, s := range report.Services {
		queue = append(queue, pending{svc: s, depth: 0})
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		key := cascadeKey(cur.svc)
		if visited[key] {
			continue // cycle guard
		}
		visited[key] = true
		if cur.depth > o.cfg.MaxCascadeDepth {
			o.logger.Debug("cascade depth exceeded, stopping", "service", cur.svc.Service, "depth", cur.depth)
			continue
		}

		handler := o.reg.HandlerFor(cur.svc.Service)
		if handler == nil {
			continue // no handler for this service; that's fine
		}

		svcCtx := ServiceContext{
			IP:       report.IP,
			Identity: cur.svc,
			Device:   report.Device,
			Evidence: report.Evidence,
		}
		// Fold cascade context into identity metadata for the handler to read.
		if cur.context != nil {
			if svcCtx.Identity.Metadata == nil {
				svcCtx.Identity.Metadata = map[string]string{}
			}
			for k, v := range cur.context {
				svcCtx.Identity.Metadata[k] = v
			}
		}

		data, triggers, err := handler.Collect(ctx, svcCtx)
		if err != nil {
			o.logger.Debug("handler collect failed", "service", cur.svc.Service, "ip", report.IP, "error", err)
		}
		if data != nil {
			report.Collected[cur.svc.Service] = data
		}
		// Always apply enrichment (even when Collect returned no data — many
		// handlers like Camera/SSH/RTSP do all their work in EnrichDevice and
		// return nil data). Re-snapshot the device so handlers see prior edits.
		svcCtx.Device = report.Device
		handler.EnrichDevice(svcCtx, data)
		report.Device = svcCtx.Device

		// Generate heartbeat for the original (depth-0) services. Cascaded
		// services usually inherit the parent's heartbeat (e.g. node_exporter
		// rides on the prometheus scrape), so we skip them by default.
		if cur.depth == 0 {
			if hb := handler.GenerateHeartbeat(svcCtx); hb != nil {
				report.Heartbeats = append(report.Heartbeats, *hb)
			}
		}

		// Enqueue cascaded triggers.
		for _, t := range triggers {
			queue = append(queue, pending{
				svc: ServiceIdentity{
					Service:  t.Service,
					Port:     t.Port,
					Metadata: t.Context,
				},
				context: t.Context,
				depth:   cur.depth + 1,
			})
		}
	}

	// Persist device enrichment + heartbeats (Phase 1).
	if o.repo != nil {
		if err := o.repo.RecordDevice(ctx, report.IP, report.Device); err != nil {
			o.logger.Debug("record device failed", "ip", report.IP, "error", err)
		}
		if err := o.repo.RecordHeartbeats(ctx, report.IP, report.Heartbeats); err != nil {
			o.logger.Debug("record heartbeats failed", "ip", report.IP, "error", err)
		}
	}
}

// cascadeKey is the dedup key for the cycle guard: service@port.
func cascadeKey(s ServiceIdentity) string {
	return s.Service + "@" + itoa(s.Port)
}

// itoa avoids strconv import in this file.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
