// Package engine assembles the scannerv2 layers (probes, classifiers, handlers,
// persistence, eBPF observer) into a single Engine that the API layer
// constructs once at startup and reuses per scan request.
//
// This package exists to break what would otherwise be an import cycle: the
// root scannerv2 package defines the shared types and the orchestrator, while
// the sub-packages (probe, classify, handler, store, ebpf) implement the
// layers against those types. Only this engine package is allowed to import
// all of them together.
package engine

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	fp "mibee-fingerprints-go"

	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/classify"
	"mibee-steward/internal/service/scannerv2/ebpf"
	"mibee-steward/internal/service/scannerv2/handler"
	"mibee-steward/internal/service/scannerv2/probe"
	"mibee-steward/internal/service/scannerv2/store"
	"mibee-steward/internal/service/scannerv2/vendor"
)

// Engine bundles everything the API layer needs to run a v2 scan: the
// configured orchestrator (registry wired with probes/classifiers/handlers),
// the persistence repository, and the eBPF observer.
type Engine struct {
	Orchestrator *scannerv2.Orchestrator
	Registry     *scannerv2.Registry
	Repository   scannerv2.Repository
	// perProbeTimeout bounds each individual probe attempt (passed to probes
	// via ProbeHint.Timeout). Stored on Engine so ScanTargets can read it
	// without re-deriving. <=0 falls back to 3s at use time.
	perProbeTimeout time.Duration
	// snmpCommunity is the default SNMP community string, passed to the SNMP
	// probe via ProbeHint.Community. Empty → probe defaults to "public".
	snmpCommunity string
	// scanSem caps the number of concurrent top-level scans (sync POST /scan +
	// cron-triggered task runs). Caps total resource use across the process;
	// per-host parallelism within a scan is governed by Orchestrator config.
	// A caller blocks on scanSem <- struct{}{} until a slot is free, releasing
	// it when the scan returns. <=0 means unbounded.
	scanSem chan struct{}
}

// Config carries the v2 engine tuning. It is derived from config.Config
// in the API/routes layer (so scannerv2 stays free of config imports).
type Config struct {
	// PortSpec is the TCP port range to scan (e.g. "22,80,443,8080,554,8554,9090,9100").
	// Empty → fingerprint ports only.
	PortSpec string
	// MaxConcurrentHosts caps per-scan parallelism (default 50).
	MaxConcurrentHosts int
	// PerHostTimeout bounds one host's full pipeline (default 30s). Enforced via
	// the per-host context deadline in ScanTargets — the upper bound for ALL
	// probes + handlers + cascade on a single host.
	PerHostTimeout time.Duration
	// PerProbeTimeout bounds a SINGLE probe attempt (one SNMP Get, one TCP dial,
	// one HTTP fetch). This is distinct from PerHostTimeout: a dead host should
	// fail fast (a few seconds) on each probe, not consume the whole host budget.
	// Without this cap, gosnmp/TCP dials on unresponsive hosts block for up to
	// PerHostTimeout (e.g. 5min), making /24 scans take 25+ minutes.
	PerProbeTimeout time.Duration
	// MaxConcurrentScans caps the number of top-level scans that may run at once
	// across the whole process (sync requests + cron tasks). <=0 disables the
	// limit. Backs the scanner.max_concurrent_scans config key.
	MaxConcurrentScans int
	// PersistRawEvidence toggles writing raw evidence rows (default off).
	PersistRawEvidence bool
	// OUIPath is the path to the IEEE OUI vendor-mapping file (optional). When
	// empty or missing, the ARP probe still records MAC addresses but skips the
	// vendor lookup. The path is overridable via MIBEE_SCANNER_OUI_PATH.
	OUIPath string
	// FingerprintPath is the directory of fingerprint YAML files (see
	// configs/fingerprints/ + docs/fingerprint-spec.md). When set, the
	// RuleClassifier loads rules from it. When empty, the engine falls back to
	// the fingerprint rules embedded in the binary (fingerprint-assets/), so
	// data-driven classification works with zero config. Overridable via
	// MIBEE_SCANNER_FINGERPRINT_PATH.
	FingerprintPath string
	// SNMPCommunity is the default community string passed to the SNMP probe
	// via ProbeHint.Community (default "public" if empty).
	SNMPCommunity string
	// RouterARP enables cross-subnet MAC resolution by walking routers' SNMP
	// ARP tables (ipNetToMediaPhysAddress). Empty routers → cross-subnet MAC is
	// disabled and the scanner falls back to /proc/net/arp (local subnet only).
	RouterARP probe.RouterARPConfig
	// HeartbeatInterval/Timeout are the defaults applied to generated configs.
	HeartbeatInterval int
	HeartbeatTimeout  int
	// NetworkID is the networks.id this engine tags discovered devices with
	// (devices.network_id). 0 leaves network_id NULL (legacy/unresolved).
	// Resolved from config `network` at startup; enables multi-LAN coexistence.
	NetworkID int64
	// EBPF controls the passive observer (no-op when disabled or stub build).
	EBPF ebpf.Config
}

// NewEngine constructs the full v2 engine: registry populated with the default
// probe/classifier/handler sets + the eBPF observer, an orchestrator, and a
// SQLite-backed repository. db may be nil for a no-persistence engine (tests).
func NewEngine(db *sql.DB, cfg Config, logger *slog.Logger) (*Engine, error) {
	if logger == nil {
		logger = slog.Default()
	}

	reg := scannerv2.NewRegistry()

	// Load the OUI vendor table once (silent degradation if the file is absent
	// — the ARP probe still records MAC addresses, just without vendor).
	oui := vendor.New()
	if cfg.OUIPath != "" {
		if err := oui.Load(cfg.OUIPath); err != nil {
			logger.Warn("scannerv2: OUI file load failed; vendor lookup disabled",
				"path", cfg.OUIPath, "error", err)
		} else if oui.Loaded() {
			logger.Info("scannerv2: OUI vendor table loaded",
				"path", cfg.OUIPath, "entries", oui.Size())
		} else {
			logger.Info("scannerv2: OUI file not present; vendor lookup disabled (MAC still recorded)",
				"path", cfg.OUIPath)
		}
	} else {
		logger.Info("scannerv2: no OUI path configured; vendor lookup disabled (MAC still recorded)")
	}

	// ① Probes: active set + optional passive eBPF observer.
	for _, p := range probe.DefaultProbeSources(cfg.PortSpec, oui) {
		reg.RegisterProbe(p)
	}
	observer := ebpf.New(cfg.EBPF)
	reg.RegisterProbe(observer)
	if cfg.EBPF.Enabled {
		logger.Info("scannerv2: eBPF passive observer enabled",
			"interfaces", cfg.EBPF.Interfaces,
			"note", "active only if binary built with WITH_EBPF tag")
	}

	// ② Classifiers. The RuleClassifier comes from the standalone fingerprint
	// library (mibee-fingerprints-go). It loads data-driven YAML rules — from
	// FingerprintPath when configured, else from the rules embedded in the
	// library binary (zero-config). Hand-written logic classifiers (SNMP bitmask
	// heuristic, Camera cross-evidence fusion) run alongside.
	rc := &fp.RuleClassifier{}
	if cfg.FingerprintPath != "" {
		if err := rc.LoadFromDir(cfg.FingerprintPath); err != nil {
			logger.Error("scannerv2: fingerprint dir load failed; falling back to embedded rules",
				"path", cfg.FingerprintPath, "error", err)
			_ = rc.LoadEmbeddedDefaults()
		} else if rc.Loaded() {
			logger.Info("scannerv2: fingerprints loaded from dir",
				"path", cfg.FingerprintPath, "rules", rc.RuleCount())
		} else {
			logger.Info("scannerv2: fingerprint dir empty; falling back to embedded rules",
				"path", cfg.FingerprintPath)
			_ = rc.LoadEmbeddedDefaults()
		}
	} else {
		if err := rc.LoadEmbeddedDefaults(); err != nil {
			logger.Warn("scannerv2: embedded fingerprint load failed; data-driven rules disabled",
				"error", err)
		}
	}
	if rc.Loaded() {
		logger.Info("scannerv2: fingerprint rules active", "rules", rc.RuleCount())
	}
	for _, c := range classify.DefaultClassifiers(rc) {
		reg.RegisterClassifier(c)
	}

	// ③ ServiceHandlers.
	for _, h := range handler.DefaultHandlers() {
		reg.RegisterHandler(h)
	}

	// ④ Persistence (nil DB → no-op repository).
	var repo scannerv2.Repository = scannerv2.NoopRepository{}
	if db != nil {
		repo = store.NewSQLiteRepository(db, store.Options{
			PersistRawEvidence:       cfg.PersistRawEvidence,
			DefaultHeartbeatInterval: cfg.HeartbeatInterval,
			DefaultHeartbeatTimeout:  cfg.HeartbeatTimeout,
			NetworkID:                cfg.NetworkID,
		}, logger)
	}

	orch := scannerv2.NewOrchestrator(reg, repo, scannerv2.OrchestratorConfig{
		MaxConcurrentHosts: cfg.MaxConcurrentHosts,
		PerHostTimeout:     cfg.PerHostTimeout,
	}, logger)
	// Inject the post-scan MAC resolver so cold scans still capture MAC after the
	// ICMP/TCP probes have populated the kernel ARP cache. The engine (not the
	// scannerv2 root package) wires this to avoid an import cycle. The closure
	// carries the OUI table so the synthesized evidence includes the vendor.
	//
	// Resolution order: (1) /proc/net/arp (local subnet, populated by the ICMP
	// probe during gather); (2) when that misses AND routers are configured,
	// walk the router's SNMP ARP table (cross-subnet). The first hit wins.
	routerCfg := cfg.RouterARP
	probe.SetPostScanResolver(func(ip string) (mac, device, vendor string) {
		m, d := probe.LookupMACPostScan(ip)
		if m == "" && len(routerCfg.Routers) > 0 {
			// Cross-subnet: ask the router. The OUI lookup happens below on
			// whichever MAC we end up with.
			ctx, cancel := context.WithTimeout(context.Background(), routerCfg.Timeout)
			if rm, ok := probe.LookupMACViaRouters(ctx, routerCfg, ip); ok {
				m = rm
			}
			cancel()
		}
		if m == "" {
			return "", "", ""
		}
		v := ""
		if oui != nil {
			v = oui.Lookup(m)
		}
		return m, d, v
	})
	orch.SetMACResolver(probe.ResolveMACPostScan)

	logger.Info("scannerv2 engine ready", "registry", reg.String())
	e := &Engine{Orchestrator: orch, Registry: reg, Repository: repo}
	// Per-probe timeout: bound each probe attempt so a dead host fails in
	// seconds instead of consuming the whole per-host budget. Default 3s.
	e.perProbeTimeout = cfg.PerProbeTimeout
	if e.perProbeTimeout <= 0 {
		e.perProbeTimeout = 3 * time.Second
	}
	e.snmpCommunity = cfg.SNMPCommunity
	logger.Info("scannerv2: per-probe timeout", "timeout", e.perProbeTimeout)
	if e.snmpCommunity != "" && e.snmpCommunity != "public" {
		logger.Info("scannerv2: SNMP community override configured", "community", e.snmpCommunity)
	}
	if cfg.MaxConcurrentScans > 0 {
		e.scanSem = make(chan struct{}, cfg.MaxConcurrentScans)
		logger.Info("scannerv2: concurrent-scan cap enabled", "max", cfg.MaxConcurrentScans)
	}
	return e, nil
}

// EstimateTargetCount parses the target spec and returns the number of IPs it
// would scan, WITHOUT executing. Used by the API layer to reject synchronous
// scans that would exceed a safe duration (callers should use the async task
// API for large ranges). Returns an error on invalid specs.
func (e *Engine) EstimateTargetCount(targets string) (int, error) {
	ips, err := parseScanTargets(targets)
	if err != nil {
		return 0, err
	}
	return len(ips), nil
}

// ScanTargets fans Run out across multiple IPs/CIDRs with concurrency control.
// It parses the target spec, runs the orchestrator per host, and returns one
// HostReport per alive host (dead hosts are omitted from the result but still
// persisted as not-alive via Run's persistence path).
func (e *Engine) ScanTargets(ctx context.Context, targets string, fastScan bool) ([]scannerv2.HostReport, error) {
	ips, err := parseScanTargets(targets)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no targets to scan")
	}

	// Acquire a global scan slot so N concurrent scans can't overload the host
	// even when many sync requests or cron tasks fire at once. Released on
	// return (including error/ctx-cancel). No-op when scanSem is nil (unbounded).
	if e.scanSem != nil {
		select {
		case e.scanSem <- struct{}{}:
			defer func() { <-e.scanSem }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	maxConc := e.Orchestrator.MaxConcurrentHosts()
	// Per-probe timeout (NOT per-host): each probe attempt on each host gets
	// this long. A dead host fails in seconds across all its probes rather than
	// blocking the full PerHostTimeout on each. The per-host pipeline ceiling
	// is enforced separately by the hostCtx deadline below.
	hint := scannerv2.ProbeHint{Timeout: e.perProbeTimeout, Community: e.snmpCommunity}

	reports := make([]scannerv2.HostReport, len(ips))
	sem := make(chan struct{}, maxConc)
	var wg sync.WaitGroup
	for i, ip := range ips {
		select {
		case <-ctx.Done():
			return reports[:i], ctx.Err()
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, hostIP string) {
			defer wg.Done()
			defer func() { <-sem }()
			// Always bound per-host time. Previously only fastScan applied a
			// timeout, so a hung probe on a single unresponsive host in normal
			// mode could block the whole scan until the server WriteTimeout
			// fired. With a per-host deadline the rest of the /24 still completes.
			// (fastScan just uses the same PerHostTimeout; it no longer needs a
			// special branch since the timeout is now always applied.)
			_ = fastScan // retained for signature stability; no longer branched on
			perHost := e.Orchestrator.PerHostTimeout()
			hostCtx, cancel := context.WithTimeout(ctx, perHost)
			defer cancel()
			reports[idx] = e.Orchestrator.Run(hostCtx, hostIP, hint)
		}(i, ip)
	}
	wg.Wait()

	// Compact: drop dead hosts from the returned slice.
	alive := reports[:0]
	for _, r := range reports {
		if r.Alive {
			alive = append(alive, r)
		}
	}
	return alive, nil
}
