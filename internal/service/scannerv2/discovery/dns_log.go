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
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// DNSLogSource tails a dnsmasq query log (dnsmasq --log-queries output) and
// emits a NewHostEvent for each query a LAN device makes. It is a router-
// resident signal: the gateway is typically the LAN's recursive resolver, so
// its DNS log is the authoritative "what is each device asking for" view — a
// powerful passive fingerprint (a device querying ntp.android.com is Android;
// time.apple.com is Apple; a sudden new C2 domain is behavior of interest).
//
// Why it matters (Tier-1 router-only signal — see
// docs/private/architecture-debt-and-openwrt-2026-07-27.md §3.2):
//
//   - Complements ACTIVE identification (SNMP/RTSP/ONVIF banners): DNS reveals
//     device identity + behavior without sending a single probe packet. Devices
//     that block all inbound probes still make outbound DNS.
//   - The queried domain is a strong OS/vendor hint (the existing fingerprint
//     corpus could be extended with a DNS-domain→vendor map in a follow-up).
//
// Operator setup: dnsmasq must run with --log-queries (UCI:
// `uci set dhcp.@dnsmasq[0].logqueries=1`) and write to a file (either via
// syslog filtering or --log-facility=<path>). The source reads whichever path
// the operator points it at (scanner.discovery.dns_log.path); when empty it
// probes the conventional locations. Without that setup the source no-ops
// (file absent → debug log + skip), the same graceful pattern as the other
// router sources.
//
// Implementation: tail-F semantics over polling. Each sweep seeks to the last
// read offset, reads to EOF, parses query lines, emits events, and remembers
// the new offset. If the file shrank (rotated/truncated) the offset resets to
// 0 and reading starts fresh. This avoids a long-running subprocess (no
// `tail`/`logread` dependency) and slots into the same interval-poll loop the
// other sources use.
//
// P0 scope: emits the QUERYING host (IP) as a sighting + carries the queried
// domain as a hint (Hints["dns_query"]). Domain→vendor enrichment is a follow-
// up (needs a new YAML table + a classifier hook); the host-event + raw hint
// here is the high-value, low-risk first cut all three deployment forms get.
type DNSLogSource struct {
	logFiles []string // paths probed in order; first that exists is tailed
	interval time.Duration
	svc      *Service
	logger   *slog.Logger

	mu     sync.Mutex
	offset map[string]int64 // path → last-read byte offset (per tailed file)
}

// NewDNSLogSource constructs the source. interval is the poll cadence (60s).
// logFile is optional; when empty the conventional dnsmasq log paths are probed.
func NewDNSLogSource(interval time.Duration, logFile string, svc *Service, logger *slog.Logger) *DNSLogSource {
	if logger == nil {
		logger = slog.Default()
	}
	files := []string{
		"/var/log/dnsmasq.log", // explicit --log-facility (common)
		"/tmp/dnsmasq.log",     // OpenWrt ramdisk (often via logread redirect)
		"/var/log/messages",    // syslog fallback (when dnsmasq logs to syslog)
		"/var/log/syslog",      // Debian rsyslog default
	}
	if logFile != "" {
		files = []string{logFile}
	}
	return &DNSLogSource{
		logFiles: files,
		interval: interval,
		svc:      svc,
		logger:   logger,
		offset:   map[string]int64{},
	}
}

// Start launches the poll goroutine (immediate first sweep, then ticks).
func (s *DNSLogSource) Start(ctx context.Context) {
	go s.loop(ctx)
}

func (s *DNSLogSource) loop(ctx context.Context) {
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

// sweep tails each candidate log file from the last-read offset, parses dnsmasq
// query lines, and emits an event per (querier IP, domain). A missing/unreadable
// file is logged once-per-call at debug and tolerated.
func (s *DNSLogSource) sweep() {
	for _, path := range s.logFiles {
		s.tailFile(path)
	}
}

// tailFile reads new bytes from one log file (since the last sweep) and parses
// them. Separate from sweep() so the offset bookkeeping is per-file.
func (s *DNSLogSource) tailFile(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return // file absent (host not running dnsmasq query logging) — skip
	}
	f, err := os.Open(path)
	if err != nil {
		s.logger.Debug("discovery: dns_log open failed", "path", path, "error", err)
		return
	}
	defer f.Close()

	s.mu.Lock()
	prevOff := s.offset[path]
	s.mu.Unlock()

	// If the file shrank since last read (rotated/truncated), restart from the
	// beginning; otherwise seek to where we left off. Don't tail from offset 0 on
	// the very first sweep of a huge existing log — start at EOF to avoid replaying
	// history (only NEW queries going forward are interesting).
	curSize := info.Size()
	if prevOff == 0 {
		// First sight of this file: skip existing content, tail from EOF.
		prevOff = curSize
	}
	if curSize < prevOff {
		// Rotation/truncation: the file is smaller than our last offset. Restart
		// from the beginning rather than seeking past EOF.
		prevOff = 0
	}
	if _, err := f.Seek(prevOff, 0); err != nil {
		s.logger.Debug("discovery: dns_log seek failed", "path", path, "error", err)
		return
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // syslog lines can be long
	newOff := prevOff
	count := 0
	for sc.Scan() {
		line := sc.Text()
		// Track bytes read (line + newline) so the next sweep resumes correctly.
		newOff += int64(len(line)) + 1
		ip, domain := parseDnsmasqQuery(line)
		if ip == "" || domain == "" {
			continue
		}
		s.svc.Emit(NewHostEvent{
			IP:     ip,
			Source: "dns_log",
			Hints: map[string]string{
				"discovery_note": "dns",
				"dns_query":      domain,
			},
		})
		count++
	}
	if err := sc.Err(); err != nil {
		s.logger.Debug("discovery: dns_log scan failed", "path", path, "error", err)
		// Still update offset to where we got — partial progress is fine.
	}
	// Always persist the resume offset. The first-sweep EOF case (prevOff reset
	// to curSize, zero lines read) MUST record curSize so the next sweep resumes
	// at EOF rather than replaying the whole file every sweep.
	s.mu.Lock()
	s.offset[path] = newOff
	s.mu.Unlock()
	if count > 0 {
		s.logger.Debug("discovery: dns_log sweep", "path", path, "queries", count)
	}
}

// parseDnsmasqQuery extracts the (querier IP, domain) from a dnsmasq query log
// line. Returns ("", "") for non-query lines (forwarded/reply/config lines,
// unrelated syslog noise). Recognizes the two common line shapes dnsmasq emits
// with --log-queries:
//
//	< preamble > dnsmasq[<pid>]: query[<type>] <domain> from <ip>
//	< preamble > dnsmasq[<pid>]: <type> <domain> is <ip>          (config/static)
//
// Only the first (an actual client query) reveals the *querying* device — that's
// what we emit. "is" lines tell us a name→ip mapping but not who asked.
func parseDnsmasqQuery(line string) (ip, domain string) {
	// Must be a dnsmasq line.
	idx := strings.Index(line, "dnsmasq")
	if idx < 0 {
		return "", ""
	}
	rest := line[idx:]
	// Must be a "query[...]" line (the only shape that carries "... from <ip>").
	qIdx := strings.Index(rest, "query[")
	if qIdx < 0 {
		return "", ""
	}
	rest = rest[qIdx:]
	// rest looks like: query[A] example.com from 192.168.1.50
	// Find the closing bracket, then split the remainder on " from ".
	closeBracket := strings.IndexByte(rest, ']')
	if closeBracket < 0 {
		return "", ""
	}
	rest = strings.TrimSpace(rest[closeBracket+1:])
	fromIdx := strings.LastIndex(rest, " from ")
	if fromIdx < 0 {
		return "", ""
	}
	domain = strings.TrimSpace(rest[:fromIdx])
	ip = strings.TrimSpace(rest[fromIdx+len(" from "):])
	// Trim a trailing port/pid if present (defensive — dnsmasq doesn't emit one,
	// but a syslog relay might append junk).
	if sp := strings.IndexByte(ip, ' '); sp >= 0 {
		ip = ip[:sp]
	}
	if domain == "" || ip == "" {
		return "", ""
	}
	// Reject obviously-non-IP queriers (sometimes dnsmasq logs "from <iface>" for
	// locally-originated queries — not a host sighting).
	if !looksLikeIPv4(ip) {
		return "", ""
	}
	return ip, domain
}

// looksLikeIPv4 is a cheap a.b.c.d validator (no port, 4 octets). Used to reject
// "query ... from eth0" lines (interface, not a host) without pulling in net.IP.
func looksLikeIPv4(s string) bool {
	octets := 0
	cur := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if octets >= 3 || cur > 255 {
				return false
			}
			octets++
			cur = 0
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		cur = cur*10 + int(c-'0')
		if cur > 255 {
			return false
		}
	}
	return octets == 3
}

// String returns a debug label for the source (which file(s) it's probing).
// Unused for now but handy for the status endpoint follow-up.
func (s *DNSLogSource) String() string { return fmt.Sprintf("dns_log(paths=%v)", s.logFiles) }
