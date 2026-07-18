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
	IP         string
	Alive      bool
	RTTMs      int64
	Evidence   []Evidence
	Services   []ServiceIdentity
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
	reg  *Registry
	repo Repository // may be nil (no persistence)
	cfg  OrchestratorConfig
	// cfgMu guards the mutable tuning fields (PerHostTimeout, MaxConcurrentHosts)
	// which SetTimeouts writes from one goroutine (the task runner / sync-scan
	// handler) while Run/ScanTargets read them from many. The rest of cfg is
	// immutable after construction.
	cfgMu  sync.RWMutex
	logger *slog.Logger
	// macResolver re-reads the kernel ARP cache after gather, closing the race
	// where the concurrent ARPProbe runs before ICMP has populated the cache.
	// Returns (mac, device, vendor) — vendor comes from the OUI lookup the
	// engine wires in via probe.SetPostScanResolver. nil (default) disables the
	// post-scan MAC re-read. Injected by the engine layer to avoid a
	// scannerv2 → probe → scannerv2 import cycle.
	macResolver func(ip string) (mac, device, vendor string)
	// neighborIdentityInfer is called during the neighbor enrichment pass to infer
	// device identity (vendor/model/type) from neighbor evidence carrying identity
	// keys (sys_name, sys_desc, platform, version). Returns a map of fields to
	// enrich on the neighbor device, or nil if no inference can be made. nil
	// (default) disables enrichment.
	neighborIdentityInfer func(localMAC, neighborMAC, sysName, sysDesc, platform string) map[string]string
}

// SetMACResolver injects a post-scan MAC resolver (see ResolveMACPostScan in
// package probe). Passing nil disables the re-read. Safe to call once at engine
// construction time.
func (o *Orchestrator) SetMACResolver(f func(ip string) (mac, device, vendor string)) {
	o.macResolver = f
}

// SetNeighborIdentityInfer injects a neighbor identity inference callback used
// during the enrichment pass after RecordNeighbors. nil (default) disables
// enrichment. Safe to call once at engine construction time.
func (o *Orchestrator) SetNeighborIdentityInfer(f func(localMAC, neighborMAC, sysName, sysDesc, platform string) map[string]string) {
	o.neighborIdentityInfer = f
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

	// Post-gather MAC re-read: the concurrent ARPProbe may have run before the
	// ICMP/TCP probes populated the kernel's neighbour cache, missing the entry
	// on a cold scan. By now gather has completed, so re-query the cache and
	// synthesize a "mac" evidence if one wasn't already collected. This lifts
	// cold-scan MAC coverage from ~3% to ~60%+ in testing. The resolver also
	// carries the OUI-derived vendor so the synthesized evidence matches the
	// shape ARPProbe emits.
	if o.macResolver != nil && !hasEvidenceKind(evidence, "mac") {
		if mac, dev, vendor := o.macResolver(ip); mac != "" {
			raw := map[string]string{"mac": mac, "device": dev}
			if vendor != "" {
				raw["vendor"] = vendor
			}
			ev := Evidence{
				Source:     "active:arp",
				Kind:       "mac",
				IP:         ip,
				Protocol:   "arp",
				RawData:    raw,
				Confidence: 1.0,
				ObservedAt: time.Now(),
			}
			evidence = append(evidence, ev)
			report.Evidence = evidence
		}
	}

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

// hasEvidenceKind reports whether any evidence in ev has the given Kind.
func hasEvidenceKind(ev []Evidence, kind string) bool {
	for _, e := range ev {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

// stripWildcardPrefix removes a leading "*." from a TLS cert CN so it reads as
// a hostname ("*.hikvision.com" → "hikvision.com"). CNs without a wildcard are
// returned unchanged.
func stripWildcardPrefix(cn string) string {
	if len(cn) >= 2 && cn[0] == '*' && cn[1] == '.' {
		return cn[2:]
	}
	return cn
}

// httpServerToBrand extracts a coarse product/vendor label from an HTTP Server
// header, used only as a last-resort brand when SNMP/cert/OUI yielded nothing.
// Returns "" for servers that don't map to a clear product (the vast majority).
func httpServerToBrand(server string) string {
	switch {
	case containsFold(server, "nginx"):
		return "nginx"
	case containsFold(server, "apache"):
		return "Apache"
	case containsFold(server, "caddy"):
		return "Caddy"
	case containsFold(server, "iis") || containsFold(server, "microsoft"):
		return "Microsoft IIS"
	case containsFold(server, "lighttpd"):
		return "lighttpd"
	}
	return ""
}

// hasCameraEvidence reports whether the host produced RTSP-banner or ONVIF
// response evidence — i.e. it is (very likely) a camera. Used to suppress
// using the HTTP Server header (nginx/Apache reverse proxy) as the device
// brand, since that software is not the camera's vendor.
func hasCameraEvidence(ev []Evidence) bool {
	for _, e := range ev {
		if e.Kind == "rtsp_banner" || e.Kind == "onvif_response" {
			return true
		}
	}
	return false
}

// isWebServerName reports whether a brand string is a generic web-server
// software name (nginx, Apache, Caddy, etc.) rather than a real device vendor.
// Used by the TLS evidence fold to decide whether a cert-derived brand should
// override the HTTP Server header brand.
func isWebServerName(brand string) bool {
	switch lowerASCII(brand) {
	case "nginx", "apache", "caddy", "lighttpd", "microsoft iis":
		return true
	}
	return false
}

// certCNToBrand extracts a vendor name from a TLS certificate's subject CN.
// Mirrors the classifier's vendorFromCertCN keyword matching, but runs in the
// orchestrator's evidence fold so the brand reaches Device.Fields (the path
// the device record reads from). Without this, TLS-derived brands (OpenWrt,
// GL.iNet, Hikvision, etc.) stay in identity metadata and never reach the
// device's scan_attributes.brand.
func certCNToBrand(cn string) string {
	lower := lowerASCII(cn)
	switch {
	case containsFold(lower, "hikvision") || containsFold(lower, "hik"):
		return "Hikvision"
	case containsFold(lower, "dahua"):
		return "Dahua"
	case containsFold(lower, "axis"):
		return "Axis"
	case containsFold(lower, "unifi") || containsFold(lower, "ubiquiti"):
		return "Ubiquiti"
	case containsFold(lower, "synology"):
		return "Synology"
	case containsFold(lower, "qnap"):
		return "QNAP"
	case containsFold(lower, "cisco"):
		return "Cisco"
	case containsFold(lower, "fortinet") || containsFold(lower, "fortigate"):
		return "Fortinet"
	case containsFold(lower, "openwrt"):
		return "OpenWrt"
	case containsFold(lower, "istoreos"):
		return "iStoreOS"
	case containsFold(lower, "gl-inet") || containsFold(lower, "glinet"):
		return "GL.iNet"
	}
	return ""
}

// certFieldsToBrand checks both subject_cn and issuer_org for vendor keywords.
// Some devices (iStoreOS routers) put the product name in subject_cn and
// "OpenWrt" in issuer_org — checking both maximizes coverage.
func certFieldsToBrand(subjectCN, issuerOrg string) string {
	if b := certCNToBrand(subjectCN); b != "" {
		return b
	}
	return certCNToBrand(issuerOrg)
}

func containsFold(s, substr string) bool {
	return len(s) >= len(substr) && (containsFoldImpl(s, substr))
}

func containsFoldImpl(s, substr string) bool {
	// case-insensitive substring without pulling strings into the root package
	// (classify already imports strings; orchestrator deliberately doesn't).
	ls := lowerASCII(s)
	lt := lowerASCII(substr)
	for i := 0; i+len(lt) <= len(ls); i++ {
		if ls[i:i+len(lt)] == lt {
			return true
		}
	}
	return false
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// ssdpServerToOS extracts a coarse OS label from an SSDP SERVER header. The
// header conventionally begins with "<OS>/<version>" (e.g. "Linux/4.4",
// "Windows/10.0", "macOS/12.5"). Returns "" for unparseable values.
func ssdpServerToOS(server string) string {
	if server == "" {
		return ""
	}
	// Take the first whitespace-delimited token, split on '/', keep the prefix.
	first := server
	if i := indexByte(server, ' '); i > 0 {
		first = server[:i]
	}
	if i := indexByte(first, '/'); i > 0 {
		return first[:i]
	}
	return ""
}

// ssdpServerToBrand pulls a product/brand token from the SSDP SERVER header
// tail (the third token, e.g. "MyDevice/1.0" in "Linux/4.4 UPnP/1.1 MyDevice/1.0").
// Returns "" when no product token is recognizable.
func ssdpServerToBrand(server string) string {
	if server == "" {
		return ""
	}
	tokens := splitWS(server)
	// Typical shape: OS/ver UPnP/ver Product/ver — product is the 3rd token.
	// Guard against short SERVER headers ("Linux/4.4" alone, etc.).
	if len(tokens) < 3 {
		return ""
	}
	for _, t := range tokens[2:] {
		// Skip the generic UPnP/SSDP tokens.
		if containsFold(t, "upnp") || containsFold(t, "ssdp") {
			continue
		}
		if i := indexByte(t, '/'); i > 0 {
			return t[:i]
		}
		return t
	}
	return ""
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func splitWS(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
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
func (o *Orchestrator) dispatch(ctx context.Context, report *HostReport, _ ProbeHint) {
	// Seed device ref for handlers to mutate.
	if report.Device.IP == "" {
		report.Device = DeviceRef{IP: report.IP, Fields: map[string]string{}}
	}
	if report.Device.Fields == nil {
		report.Device.Fields = map[string]string{}
	}

	// Fold host-level L2/L3 evidence (MAC + OUI vendor from the ARP probe,
	// hostname from rDNS) into DeviceRef.Fields. These are host-level facts
	// that no per-service handler owns; without this fold they would be lost
	// on the store.RecordDevice path (which only sees DeviceRef, not the full
	// evidence slice). The runner's buildScanAttributes re-reads them as a
	// belt-and-suspenders measure.
	for _, e := range report.Evidence {
		if e.RawData == nil {
			continue
		}
		switch e.Kind {
		case "mac":
			if v := e.RawData["mac"]; v != "" && report.Device.Fields["mac"] == "" {
				report.Device.Fields["mac"] = v
			}
			if v := e.RawData["vendor"]; v != "" && report.Device.Fields["inferred_brand"] == "" {
				report.Device.Fields["inferred_brand"] = v
			}
		case "hostname":
			if v := e.RawData["hostname"]; v != "" && report.Device.Fields["node_hostname"] == "" {
				report.Device.Fields["node_hostname"] = v
			}
		case "tls":
			// TLS cert CN/SAN often carry the device's hostname or vendor
			// domain (e.g. "*.hikvision.com"). Prefer an explicit rDNS/mDNS
			// hostname, but fall back to a cert CN when nothing else is set.
			if v := e.RawData["subject_cn"]; v != "" && report.Device.Fields["node_hostname"] == "" {
				report.Device.Fields["node_hostname"] = stripWildcardPrefix(v)
			}
			// Derive brand from the cert CN. TLS cert vendor (OpenWrt, GL.iNet,
			// Hikvision) is a STRONGER signal than the HTTP Server header
			// (nginx/Apache), so override when the current brand looks like a
			// generic web-server name. Only set when empty for genuine device
			// brands that don't conflict.
			cnBrand := certFieldsToBrand(e.RawData["subject_cn"], e.RawData["issuer_org"])
			if cnBrand != "" {
				current := report.Device.Fields["inferred_brand"]
				if current == "" || isWebServerName(current) {
					report.Device.Fields["inferred_brand"] = cnBrand
				}
			}
		case "http":
			// The Server header sometimes carries a vendor/product string that
			// is more specific than OUI (e.g. "nginx/1.25", "Apache/2.4.58").
			// Don't overwrite a stronger SNMP/cert-derived brand. Also skip when
			// the host has RTSP/ONVIF evidence: cameras commonly front their web
			// UI with nginx/Apache, and the web-server software is NOT the camera
			// vendor — setting "nginx" as the brand of a Hikvision camera is
			// misleading. Let the OUI/cert/ONVIF brand (or empty) win instead.
			if v := e.RawData["server"]; v != "" && report.Device.Fields["inferred_brand"] == "" && !hasCameraEvidence(report.Evidence) {
				report.Device.Fields["inferred_brand"] = httpServerToBrand(v)
			}
		case "mdns":
			// mDNS carries a hostname (from SRV/A), advertised services
			// (_onvif/_rtsp/_airplay), and high-signal TXT records (model,
			// vendor, serial). Hostname fills node_hostname; vendor TXT fills
			// inferred_brand; the rest lands under mdns.* for the attribute
			// builder to surface.
			if v := e.RawData["hostname"]; v != "" && report.Device.Fields["node_hostname"] == "" {
				report.Device.Fields["node_hostname"] = v
			}
			for _, key := range []string{"txt.vendor", "txt.manufacturer", "txt.md", "txt.ty"} {
				if v := e.RawData[key]; v != "" && report.Device.Fields["inferred_brand"] == "" {
					report.Device.Fields["inferred_brand"] = v
					break
				}
			}
		case "ssdp":
			// SSDP's SERVER header is often "<OS>/<version> <product>/<ver>"
			// (e.g. "Linux/4.4 UPnP/1.1 MyDevice/1.0"). It's a strong OS hint.
			if v := e.RawData["server"]; v != "" {
				if report.Device.Fields["os_type"] == "" {
					report.Device.Fields["os_type"] = ssdpServerToOS(v)
				}
				if report.Device.Fields["inferred_brand"] == "" {
					report.Device.Fields["inferred_brand"] = ssdpServerToBrand(v)
				}
			}
		case "netbios":
			// NetBIOS returns a Windows hostname + workgroup/domain. These are
			// the only source of hostname for many Windows hosts.
			if v := e.RawData["hostname"]; v != "" && report.Device.Fields["node_hostname"] == "" {
				report.Device.Fields["node_hostname"] = v
			}
			if v := e.RawData["workgroup"]; v != "" && report.Device.Fields["netbios_workgroup"] == "" {
				report.Device.Fields["netbios_workgroup"] = v
			}
			// NOTE: do NOT infer os_type from a NetBIOS response. Samba, OpenWrt,
			// Synology DSM, and many routers/NAS appliances all run an SMB stack
			// that answers NetBIOS, so "responded to NetBIOS" is NOT evidence of
			// Windows — it was mislabeling Linux routers (e.g. an R68S running
			// dropbear + samba) as Windows. OS is now derived from stronger
			// signals only: SNMP sysDescr (osFromSysDescr), node_exporter, SSDP,
			// or SSH banner.
		}
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
		// Persist TLS certificate chains: every TLS-wrapped service handler
		// (https, ldaps, imaps, pop3s, smtps, ftps, ircs, telnets) returns a
		// TLSCertCollected payload from Collect(). We type-assert it out of the
		// Collected map and hand the records to the repo in one batch. Records
		// are best-effort like everything else here.
		if certs := extractTLSCerts(report.Collected); len(certs) > 0 {
			if err := o.repo.RecordTLSCerts(ctx, report.IP, certs); err != nil {
				o.logger.Debug("record tls certs failed", "ip", report.IP, "error", err)
			}
		}
		// Persist L2 neighbors (Phase 4): extract "neighbor"-kind evidence
		// (from the Bridge-MIB / LLDP / CDP probes) into NeighborSpecs and
		// record them. The store resolves ip→device_id and upserts edges.
		if neighbors := extractNeighbors(report.Evidence); len(neighbors) > 0 {
			if err := o.repo.RecordNeighbors(ctx, report.IP, neighbors); err != nil {
				o.logger.Debug("record neighbors failed", "ip", report.IP, "error", err)
			}
		}
		// Neighbor-identity enrichment: for each "neighbor"-kind evidence carrying
		// identity keys (sys_name, sys_desc, platform), infer fields and enrich the
		// neighbor device by MAC. Only runs when a callback is configured.
		if o.neighborIdentityInfer != nil {
			for _, e := range report.Evidence {
				if e.Kind != "neighbor" || e.RawData == nil {
					continue
				}
				neighborMAC := e.RawData["neighbor_mac"]
				if neighborMAC == "" {
					continue
				}
				sysName := e.RawData["sys_name"]
				sysDesc := e.RawData["sys_desc"]
				platform := e.RawData["platform"]
				if sysName == "" && sysDesc == "" && platform == "" {
					continue // no identity to enrich
				}
				fields := o.neighborIdentityInfer("", neighborMAC, sysName, sysDesc, platform)
				if len(fields) > 0 {
					if err := o.repo.EnrichDeviceByMAC(ctx, neighborMAC, fields); err != nil {
						o.logger.Debug("enrich device by MAC failed", "neighbor_mac", neighborMAC, "error", err)
					}
				}
			}
		}
	}
}

// cascadeKey is the dedup key for the cycle guard: service@port.
func cascadeKey(s ServiceIdentity) string {
	return s.Service + "@" + itoa(s.Port)
}

// extractNeighbors pulls L2 adjacency edges from "neighbor"-kind evidence
// (emitted by the Bridge-MIB / LLDP / CDP probes). Each evidence piece's
// RawData carries neighbor_mac + protocol + optional local/remote_port. The MAC
// is normalized (the store's RecordNeighbors expects canonical form).
func extractNeighbors(evidence []Evidence) []NeighborSpec {
	var out []NeighborSpec
	seen := map[string]bool{} // dedup (neighbor_mac, protocol) within one host
	for _, e := range evidence {
		if e.Kind != "neighbor" || e.RawData == nil {
			continue
		}
		mac := e.RawData["neighbor_mac"]
		protocol := e.RawData["protocol"]
		if mac == "" || protocol == "" {
			continue
		}
		key := mac + "|" + protocol
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, NeighborSpec{
			NeighborMAC: mac,
			Protocol:    protocol,
			LocalPort:   e.RawData["local_port"],
			RemotePort:  e.RawData["remote_port"],
		})
	}
	return out
}

// extractTLSCerts pulls every TLSCertCollected payload out of the dispatch
// result map and flattens its certificate records into a single slice for
// persistence. Multiple TLS ports on one host (e.g. https/443 + ldaps/636)
// produce multiple Collected entries; we concat them so the repo gets one batch.
// Records carrying only an Error are still forwarded — the UI uses them to show
// "we tried this port".
func extractTLSCerts(collected map[string]CollectedData) []TLSCertRecord {
	var out []TLSCertRecord
	for _, data := range collected {
		tls, ok := data.(TLSCertCollected)
		if !ok {
			continue
		}
		out = append(out, tls.Certs...)
	}
	return out
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
