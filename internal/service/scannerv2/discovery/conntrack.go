// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// ConntrackSource periodically reads the kernel conntrack table
// (/proc/net/nf_conntrack) and emits a NewHostEvent for every LAN host that has
// an active (ESTABLISHED / ASSURED) flow. It is a router-resident signal: the
// gateway is the NAT/forwarding choke point, so its conntrack table is the
// authoritative "who is talking RIGHT NOW" view — a host-based scanner on a
// random LAN box sees none of this without being a traffic tap.
//
// Why it matters (Tier-1 router-only signal — see
// docs/private/architecture-debt-and-openwrt-2026-07-27.md §3.2):
//
//   - Liveness: a device with an active flow is by definition up, even if it
//     doesn't answer ICMP or SNMP. This catches sleeping phones/IoT that wake
//     briefly to phone home, firewalled hosts that drop probes, etc.
//   - Discovery of otherwise-invisible hosts: a NAT'd client behind the router
//     that never responds to subnet sweeps but maintains an outbound flow
//     appears here.
//   - It complements (does not replace) the ARP-based sources: ARP says "this
//     MAC was seen at L2 recently"; conntrack says "this IP is generating
//     traffic RIGHT NOW".
//
// P0 scope: this source treats conntrack as a DISCOVERY + liveness signal — it
// emits the LAN-side endpoint of each flow as a host sighting, deduped the same
// way as the ARP sources. The richer per-flow topology ("device A is talking to
// external service B on port 443") requires a new persistence surface (flow
// records with src+dst+port+bytes) and is deferred — the host-event path here is
// the high-value, low-risk first cut that all three deployment forms (center /
// agent / router-center) get for free.
//
// The source filters to LAN-local endpoints (RFC1918 + link-local) so it doesn't
// emit an event for every public internet host a device talks to (which would
// flood the device table with one row per CDN IP).
type ConntrackSource struct {
	// cidr is the LAN CIDR this source considers "local" — only flows whose
	// LAN-side endpoint falls inside it are emitted. Required: without it the
	// source would emit every remote IP a device talks to.
	cidr     string
	localNet *net.IPNet
	// filePath is the conntrack table path (default /proc/net/nf_conntrack;
	// overridable via newConntrackSourceWithPath for tests).
	filePath string
	interval time.Duration
	svc      *Service
	logger   *slog.Logger

	mu       sync.Mutex
	previous map[string]bool // ip set, last sweep — for diff
}

// NewConntrackSource constructs the source. cidr is the local LAN (e.g.
// "192.168.62.0/24") used to filter which flow endpoints count as "a device we
// should record". interval is the poll cadence (typically 60s). Returns a
// usable source even when the CIDR is unparseable (logs a warning, treats every
// endpoint as remote → emits nothing), so a misconfigured CIDR degrades to a
// no-op rather than crashing.
func NewConntrackSource(cidr string, interval time.Duration, svc *Service, logger *slog.Logger) *ConntrackSource {
	return newConntrackSourceWithPath(cidr, interval, "/proc/net/nf_conntrack", svc, logger)
}

// newConntrackSourceWithPath is the test seam: same as NewConntrackSource but
// reads conntrack from an arbitrary file path (so tests can feed a fixture).
func newConntrackSourceWithPath(cidr string, interval time.Duration, filePath string, svc *Service, logger *slog.Logger) *ConntrackSource {
	if logger == nil {
		logger = slog.Default()
	}
	var localNet *net.IPNet
	if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
		localNet = ipnet
	} else {
		logger.Warn("discovery: conntrack source has invalid LAN CIDR; source will emit nothing", "cidr", cidr)
	}
	return &ConntrackSource{
		cidr:     cidr,
		localNet: localNet,
		filePath: filePath,
		interval: interval,
		svc:      svc,
		logger:   logger,
		previous: map[string]bool{},
	}
}

// Start launches the poll goroutine (immediate first sweep, then ticks).
func (s *ConntrackSource) Start(ctx context.Context) {
	go s.loop(ctx)
}

func (s *ConntrackSource) loop(ctx context.Context) {
	s.sweep()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweep()
		}
	}
}

// sweep reads /proc/net/nf_conntrack, extracts the LAN-side endpoint of each
// ESTABLISHED/ASSURED flow, diffs against the previous snapshot, and emits an
// event per newly-active host. A missing/unreadable file (nf_conntrack module
// not loaded, or /proc/sys/net/netfilter/nf_conntrack_entries not exposed) is
// logged once-per-call at debug and tolerated — the source is a no-op there.
func (s *ConntrackSource) sweep() {
	if s.localNet == nil {
		return // invalid CIDR at construction → emit nothing
	}
	hosts, err := s.readActiveLANHosts()
	if err != nil {
		s.logger.Debug("discovery: conntrack read failed (nf_conntrack unavailable?)", "error", err)
		return
	}

	current := make(map[string]bool, len(hosts))
	for ip := range hosts {
		current[ip] = true
	}

	s.mu.Lock()
	prev := s.previous
	s.previous = current
	s.mu.Unlock()

	for ip := range hosts {
		if prev[ip] {
			continue
		}
		s.svc.Emit(NewHostEvent{
			IP:     ip,
			Source: "conntrack",
			// No MAC: conntrack tracks L3+; the bridge's MAC-primary identity
			// falls back to (ip, network_id) which is correct for a flow sighting.
			// The MAC will be filled in later by an ARP/dhcp/scan sighting of the
			// same IP and the bridge reconciles by IP+network.
			Hints: map[string]string{
				"discovery_note": "conntrack",
				// active_flow flags the host as live-right-now for downstream
				// consumers (a future heartbeat-boost, or just a status hint).
				"active_flow": "true",
			},
		})
	}
	s.logger.Debug("discovery: conntrack sweep", "lan_hosts", len(hosts), "new", len(hosts)-len(prev))
}

// readActiveLANHosts parses /proc/net/nf_conntrack and returns the set of
// LAN-local IPs that appear as the LAN-side endpoint of an established flow.
//
// The conntrack entry format (one flow per line) is space-separated tokens,
// e.g.:
//
//	ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.62.41 dst=142.250.187.78 sport=443 dport=54812 ... [ASSURED] mark=0 use=2
//	ipv4 2 udp 17 29 src=192.168.62.1 dst=1.1.1.1 sport=53 dport=41220 ... [ASSURED] mark=0 use=2
//
// We look at BOTH src= and dport= and dst= and sport= because either endpoint
// may be the LAN host (a flow LAN→internet has src=LAN; a reply internet→LAN
// has dst=LAN). We take whichever of src/dst is inside the local CIDR.
func (s *ConntrackSource) readActiveLANHosts() (map[string]bool, error) {
	f, err := os.Open(s.filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	hosts := make(map[string]bool)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // conntrack lines can be long (MUD/IPv6 entries)
	for sc.Scan() {
		line := sc.Text()
		// Only count established/assured flows — a flow in SYN_SENT or TIME_WAIT
		// is not evidence of an active host (could be a half-open or a closing
		// connection). This keeps the liveness signal honest. Note conntrack
		// emits ASSURED as the bracketed token "[ASSURED]" (UDP flows have no
		// state field, only the [ASSURED] marker); ESTABLISHED is a bare state
		// token for TCP. Match both spellings.
		if !containsToken(line, "ESTABLISHED") &&
			!containsToken(line, "[ASSURED]") {
			continue
		}
		src := tokenValue(line, "src=")
		dst := tokenValue(line, "dst=")
		// Emit the endpoint that is LAN-local (at most one of the two for a
		// LAN↔internet flow; for LAN↔LAN both are, emit both).
		if src != "" && s.localNet.Contains(net.ParseIP(src)) {
			hosts[src] = true
		}
		if dst != "" && s.localNet.Contains(net.ParseIP(dst)) {
			hosts[dst] = true
		}
	}
	return hosts, sc.Err()
}

// tokenValue extracts the value of a "key=val" token from a space-separated
// line. Returns "" when the token is absent.
func tokenValue(line, key string) string {
	// Find " key=" (leading space avoids matching a substring inside another
	// token) — but the first token has no leading space, so also try at index 0.
	search := " " + key
	idx := strings.Index(line, search)
	if idx < 0 {
		if strings.HasPrefix(line, key) {
			idx = -1 // act as if found at position -1, value starts after len-1
		} else {
			return ""
		}
	}
	start := idx + len(search)
	rest := line[start:]
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		rest = rest[:sp]
	}
	return rest
}

// containsToken reports whether line contains the given whitespace-delimited
// token (e.g. "ESTABLISHED"). Avoids matching a substring inside another token.
func containsToken(line, token string) bool {
	for _, f := range strings.Fields(line) {
		if f == token {
			return true
		}
	}
	return false
}
