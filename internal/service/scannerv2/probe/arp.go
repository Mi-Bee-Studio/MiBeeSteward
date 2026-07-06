package probe

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/vendor"
)

// ARPTablePath is the Linux kernel's live ARP cache. Reading it requires NO
// privileges (it is world-readable on standard distros). Each non-comment line:
//
//	IP address   HW type   Flags   HW address            Mask   Device
//	192.168.63.1 0x1       0x2     bc:ad:28:11:22:33     *      enp3s0
const arpTablePath = "/proc/net/arp"

// LookupMACPostScan is a single-shot ARP cache lookup meant to be called AFTER
// the gather phase (which is when the ICMP/TCP probes have populated the
// kernel's neighbour table). The ARPProbe that runs concurrently during gather
// can race ahead of the ICMP probe and miss the entry on a cold scan — this
// re-read closes that window. It bypasses the 1s read cache so it always sees
// the freshest entry.
//
// Returns ("", "") when the IP has no resolved ARP entry (cross-subnet host,
// or the kernel hasn't resolved it yet). Safe to call from any goroutine.
func LookupMACPostScan(ip string) (mac, device string) {
	entries, _ := parseARPFile(arpTablePath)
	if e, ok := entries[ip]; ok {
		return e.mac, e.device
	}
	return "", ""
}

// postScanMACResolver is the OUI-aware variant set by NewARPProbe via
// SetPostScanResolver. It is invoked by the engine after gather so the
// orchestrator's synthesized "mac" evidence carries the same vendor field the
// concurrent ARPProbe would have attached. Kept as a package-level func (not a
// method) so the engine can wire it without an import cycle.
var postScanMACResolver func(ip string) (mac, device, vendor string)

// SetPostScanResolver installs the OUI-aware post-scan MAC resolver. The
// engine calls this once at construction time with a closure over the loaded
// OUI table. Passing nil reverts to the bare LookupMACPostScan behavior.
func SetPostScanResolver(f func(ip string) (mac, device, vendor string)) {
	postScanMACResolver = f
}

// ResolveMACPostScan is the orchestrator-facing resolver: returns mac, device,
// and vendor. When no OUI-aware resolver is installed (tests), vendor is "".
func ResolveMACPostScan(ip string) (mac, device, vendor string) {
	if postScanMACResolver != nil {
		return postScanMACResolver(ip)
	}
	mac, device = LookupMACPostScan(ip)
	return mac, device, ""
}

// ARPProbe resolves the target IP's MAC address from the kernel ARP cache and,
// when an OUI table is loaded, attaches the inferred vendor.
//
// It only works for hosts on a directly-attached subnet (the kernel only keeps
// ARP entries for neighbours it has spoken to L2 with). For cross-subnet hosts
// the probe returns no evidence — the MAC is simply unknown at L3.
//
// On a /24 scan the cache is normally populated by the concurrent ICMP/TCP
// probes; this probe re-reads it after the fact. To make that reliable even
// when ARP wins the race, a short retry loop is included.
//
// Name: "active:arp".
type ARPProbe struct {
	oui *vendor.OUI
}

// NewARPProbe returns an ARP probe. oui may be nil (vendor lookup is skipped).
func NewARPProbe(oui *vendor.OUI) *ARPProbe { return &ARPProbe{oui: oui} }

func (p *ARPProbe) Name() string { return "active:arp" }

// Probe resolves the MAC for ip from /proc/net/arp, retrying briefly. The hint
// is unused (no network I/O here). Returns one "mac" Evidence on success.
func (p *ARPProbe) Probe(ctx context.Context, ip string, _ scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	mac, dev := lookupMACWithRetry(ctx, ip)
	if mac == "" {
		return nil, nil
	}
	raw := map[string]string{
		"mac":    mac,
		"device": dev,
	}
	if p.oui != nil {
		if v := p.oui.Lookup(mac); v != "" {
			raw["vendor"] = v
		}
	}
	return []scannerv2.Evidence{{
		Source:     "active:arp",
		Kind:       "mac",
		IP:         ip,
		Protocol:   "arp",
		RawData:    raw,
		Confidence: 1.0, // kernel ARP cache is authoritative for L2
		ObservedAt: time.Now(),
	}}, nil
}

// lookupMACWithRetry reads /proc/net/arp up to 3 times with 200ms gaps, because
// the cache may not yet have an entry when this probe races ahead of the
// ICMP/TCP probes that trigger the kernel's neighbour discovery.
func lookupMACWithRetry(ctx context.Context, ip string) (mac, device string) {
	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-ctx.Done():
			return "", ""
		default:
		}
		m, d := lookupMACOnce(ip)
		if m != "" {
			return m, d
		}
		// Sleep 200ms before retrying (only if the ctx still has time). A bare
		// select-default would busy-loop; this keeps the worst-case added
		// latency under ~600ms even when the entry never appears.
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ""
		case <-timer.C:
		}
	}
	return "", ""
}

// cachedARP is a process-wide ARP cache snapshot. The kernel's /proc/net/arp is
// shared state, and re-reading it per-host per-probe on a /24 scan would mean
// 256 disk reads — we cache the parsed table for 1s so all hosts in one scan
// share one read.
var cachedARP struct {
	sync.Mutex
	at      time.Time
	entries map[string]arpEntry
}

type arpEntry struct {
	mac    string
	device string
}

const arpCacheTTL = 1 * time.Second

func lookupMACOnce(ip string) (string, string) {
	entries := readARPTable()
	if e, ok := entries[ip]; ok {
		return e.mac, e.device
	}
	return "", ""
}

// readARPTable returns the parsed ARP cache, using a 1s process-wide cache.
func readARPTable() map[string]arpEntry {
	cachedARP.Lock()
	defer cachedARP.Unlock()
	if time.Since(cachedARP.at) < arpCacheTTL && cachedARP.entries != nil {
		return cachedARP.entries
	}
	entries, _ := parseARPFile(arpTablePath)
	cachedARP.entries = entries
	cachedARP.at = time.Now()
	return entries
}

// parseARPFile reads /proc/net/arp into an ip→{mac,device} map. Entries with
// zero MAC ("00:00:00:00:00:00") are skipped — they represent incomplete
// resolutions.
func parseARPFile(path string) (map[string]arpEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]arpEntry)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4*1024), 64*1024)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false // skip the header row: "IP address  HW type  ..."
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		ip, mac := fields[0], fields[3]
		device := fields[5]
		if mac == "" || strings.HasPrefix(mac, "00:00:00:00:00:00") {
			continue
		}
		// Normalize MAC to lowercase so it round-trips cleanly into the JSON
		// and matches the OUI lookup's case-insensitive prefix parse.
		out[ip] = arpEntry{mac: strings.ToLower(mac), device: device}
	}
	return out, scanner.Err()
}
