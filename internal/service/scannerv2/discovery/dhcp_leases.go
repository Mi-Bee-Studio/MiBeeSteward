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
	"os"
	"strings"
	"sync"
	"time"
)

// DHCPLeasesSource periodically reads the local DHCP server's lease table and
// emits a NewHostEvent for every leased IP. It is a router-resident signal: the
// DHCP server (dnsmasq on OpenWrt, dhcpd on generic Linux) runs ON the gateway,
// so only a router/center deployed as the LAN's DHCP authority has this file.
//
// Why it matters (Tier-1 router-only signal — see
// docs/private/architecture-debt-and-openwrt-2026-07-27.md §3.2):
//
//   - It is the AUTHORITATIVE hostname↔MAC↔IP map. Every device that ever got a
//     lease is listed, including ones that don't respond to SNMP sysName, reverse
//     DNS, or ICMP (sleeping IoT, firewalled hosts, transient guests).
//   - The hostname arrives as a first-class field (the client sends it in the
//     DHCP REQUEST), so device naming no longer depends on a PTR record existing
//     in the local DNS — a frequent gap for devices the router's dnsmasq hands
//     out names to but never synthesizes PTRs for.
//
// Format parsed (dnsmasq's lease file, the OpenWrt/Debian/Devuan default):
//
//	<expiry_unix> <mac> <ipv4> <hostname> <client_id>
//	1700000000 aa:bb:cc:dd:ee:ff 192.168.1.50 phone-n13 *
//
// The hostname may be "*" when the client didn't send one. The mac is lowercased
// by dnsmasq. dhcpd's lease file (/var/lib/dhcp/dhcpd.leases) has a different
// block format and is NOT parsed here — dnsmasq is the OpenWrt/consumer-router
// default; dhcpd support can be added later behind a format probe.
type DHCPLeasesSource struct {
	// leaseFiles are the paths probed in order; the first that exists + reads is
	// used. Defaults to the conventional dnsmasq locations across distros
	// (OpenWrt /tmp/dhcp.leases, Debian /var/lib/misc/dnsmasq.leases). Override
	// via NewDHCPLeasesSource for tests.
	leaseFiles []string
	interval   time.Duration
	svc        *Service
	logger     *slog.Logger

	mu       sync.Mutex
	previous map[string]bool // "ip\x00mac" set, last sweep — for diff
}

// NewDHCPLeasesSource constructs the source. interval is the poll cadence
// (typically 60s — leases change slowly). leaseFile is optional; when empty the
// conventional dnsmasq paths are probed.
func NewDHCPLeasesSource(interval time.Duration, leaseFile string, svc *Service, logger *slog.Logger) *DHCPLeasesSource {
	if logger == nil {
		logger = slog.Default()
	}
	files := []string{
		"/tmp/dhcp.leases",             // OpenWrt / GL.iNet / Asuswrt-merlin (dnsmasq)
		"/var/lib/misc/dnsmasq.leases", // Debian / Ubuntu / Arch (dnsmasq default)
		"/var/db/dnsmasq.leases",       // BSD / macOS (dnsmasq)
	}
	if leaseFile != "" {
		files = []string{leaseFile}
	}
	return &DHCPLeasesSource{
		leaseFiles: files,
		interval:   interval,
		svc:        svc,
		logger:     logger,
		previous:   map[string]bool{},
	}
}

// Start launches the poll goroutine (immediate first sweep, then ticks).
func (s *DHCPLeasesSource) Start(ctx context.Context) {
	go s.loop(ctx)
}

func (s *DHCPLeasesSource) loop(ctx context.Context) {
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

// sweep reads the lease file, diffs against the previous snapshot, and emits an
// event for each lease not seen last sweep. A missing/unreadable file (host is
// not the DHCP server) is logged once-per-call at debug level and tolerated —
// the source is a no-op there, same as ARPCacheSource on a non-Linux host.
func (s *DHCPLeasesSource) sweep() {
	leases, path, err := s.readLeases()
	if err != nil {
		s.logger.Debug("discovery: dhcp_leases read failed (host not a DHCP server?)", "error", err)
		return
	}
	if len(leases) == 0 {
		return
	}

	current := make(map[string]bool, len(leases))
	for _, l := range leases {
		current[l.ip+"\x00"+l.mac] = true
	}

	s.mu.Lock()
	prev := s.previous
	s.previous = current
	s.mu.Unlock()

	// Emit only newly-seen leases (first sweep: everything is new). Re-emitting
	// unchanged leases every tick would re-trigger the identify pipeline; the
	// coordinator dedups against the device DB anyway, but the diff keeps the
	// event stream quiet in steady state.
	for _, l := range leases {
		if prev[l.ip+"\x00"+l.mac] {
			continue
		}
		hints := map[string]string{"discovery_note": "dhcp"}
		if l.hostname != "" && l.hostname != "*" {
			// node_hostname is the field the device bridge reads for the device's
			// name (device_bridge.go resolveHostname). foldHints only sets it when
			// the identify scan didn't already produce one, so DHCP is a fallback
			// for hosts that don't answer reverse DNS / SNMP sysName.
			hints["node_hostname"] = l.hostname
		}
		s.svc.Emit(NewHostEvent{
			IP:     l.ip,
			MAC:    l.mac,
			Source: "dhcp_leases",
			Hints:  hints,
		})
	}
	s.logger.Debug("discovery: dhcp_leases sweep", "path", path, "leases", len(leases), "new", len(leases)-len(prev))
}

// dhcpLease is one parsed row of the dnsmasq lease file.
type dhcpLease struct {
	expiry   int64
	mac      string
	ip       string
	hostname string
	clientID string
}

// readLeases opens the first existing lease file in s.leaseFiles and parses it.
// Returns the chosen path so the caller can attribute log lines.
func (s *DHCPLeasesSource) readLeases() (leases []dhcpLease, path string, err error) {
	for _, p := range s.leaseFiles {
		f, openErr := os.Open(p)
		if openErr != nil {
			continue // try next path; common case: file doesn't exist on non-DHCP hosts
		}
		path = p
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// dnsmasq format: <expiry> <mac> <ip> <hostname> <clientid>
			// duid format has extra columns; tolerate by taking the first 5.
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			var exp int64
			for _, ch := range fields[0] {
				if ch < '0' || ch > '9' {
					exp = 0
					break
				}
				exp = exp*10 + int64(ch-'0')
			}
			l := dhcpLease{
				expiry:   exp,
				mac:      strings.ToLower(fields[1]),
				ip:       fields[2],
				hostname: strings.Trim(fields[3], `"`),
			}
			if len(fields) >= 5 {
				l.clientID = fields[4]
			}
			// Skip expired leases (expiry in the past). dnsmasq leaves stale rows
			// until they're reused; an expired lease isn't a current device.
			if l.expiry != 0 && time.Now().Unix() > l.expiry {
				continue
			}
			if l.ip != "" {
				leases = append(leases, l)
			}
		}
		f.Close()
		if sc.Err() != nil {
			return leases, path, sc.Err()
		}
		return leases, path, nil
	}
	// No path existed — not an error worth retrying loudly. Caller logs at debug.
	return nil, "", os.ErrNotExist
}
