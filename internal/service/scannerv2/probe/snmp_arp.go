// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"mibee-steward/internal/service/scannerv2"
)

// ipNetToMediaPhysAddress is the OID prefix for the SNMP-standard ARP table
// (RFC 4293 ipNetToPhysicalPhysAddress is more complete but less widely
// implemented; ipNetToMedia covers virtually every SNMP-speaking router).
//
// Each row is indexed by ifIndex.ipAddress, so a Walk yields one varbind per
// neighbour with the MAC as the value. This is how nmap/masscan derive MAC
// addresses for hosts on a subnet the scanner is NOT directly attached to:
// they query the router that IS on that subnet.
const (
	oidIPNetToMediaPhysAddress = "1.3.6.1.2.1.4.22.1.2" // ipNetToMediaPhysAddress
	oidIPNetToPhysicalAddress  = "1.3.6.1.2.1.4.35.1.4" // ipNetToPhysicalPhysAddress (RFC 4293)
)

// RouterARPConfig configures the cross-subnet MAC resolver: which routers to
// query for their SNMP ARP table, and with what credentials. When empty (the
// default), cross-subnet MAC resolution is disabled and the scanner falls back
// to /proc/net/arp (local-subnet only).
type RouterARPConfig struct {
	// Routers is the list of SNMP-speaking router IPs to walk for ARP entries.
	// Typically just the subnet's default gateway.
	Routers []string
	// Community is the SNMPv2c/v1 community string (default "public").
	Community string
	// Timeout bounds each router walk.
	Timeout time.Duration
	// Cred optionally routes router ARP walks through a specific SNMP
	// credential (v1/v2c community OR SNMPv3 USM). When set it takes precedence
	// over Community. Set by the engine when a scan task binds a credential so
	// cross-subnet MAC resolution uses the same auth as the rest of the scan.
	// The passive discovery service (a separate long-running caller) does NOT
	// set this and keeps using Community — v3 there is a later enhancement.
	Cred *scannerv2.SNMPCredential
}

// LookupMACViaRouter walks a router's SNMP ARP table (ipNetToMediaPhysAddress,
// falling back to the RFC 4293 ipNetToPhysicalPhysAddress when the legacy OID
// is empty) and returns the MAC for ip when found.
//
// This is the cross-subnet counterpart to LookupMACPostScan: where the latter
// reads the local kernel's neighbour cache (only populated for the scanner's
// directly-attached subnet), this asks a router that IS on the target subnet.
// Returns ("", false) when the router doesn't speak SNMP, the OID is empty, or
// ip has no entry. Errors are swallowed deliberately — cross-subnet MAC is a
// best-effort enrichment, not a scan-critical path.
//
// The result is cached per-process for routerARPCacheTTL so a /24 cross-subnet
// scan only walks each router once instead of once-per-IP.
func LookupMACViaRouter(ctx context.Context, router, community string, timeout time.Duration, ip string) (mac string, ok bool) {
	entries := routerARPCacheGlobal.get(ctx, router, community, timeout)
	if entries == nil {
		return "", false
	}
	if m, present := entries[ip]; present {
		return m, true
	}
	return "", false
}

// LookupMACViaRouterCred is the credential-aware counterpart of
// LookupMACViaRouter: it walks the router's ARP table using a specific SNMP
// credential (v3 USM or a v1/v2c community tied to the credential) and returns
// the MAC for ip when found. Used by LookupMACViaRouters when a scan bound a
// credential. Same best-effort + cache contract as the legacy variant.
func LookupMACViaRouterCred(_ context.Context, router string, cred *scannerv2.SNMPCredential, timeout time.Duration, ip string) (mac string, ok bool) {
	entries := routerARPCacheGlobal.getCred(router, cred, timeout)
	if entries == nil {
		return "", false
	}
	if m, present := entries[ip]; present {
		return m, true
	}
	return "", false
}

// WalkRouterARPTable walks a single router's SNMP ARP table (ipNetToMediaPhysAddress,
// falling back to the RFC 4293 ipNetToPhysicalPhysAddress) and returns the full
// ip→lowercased-MAC map. It is the best-effort variant used by the per-scan MAC
// enrichment path (cross-subnet MAC resolution): the long-running passive
// discovery service instead uses WalkRouterARPTableWithErr so it can log WHY a
// router yields nothing, and diff against its previous snapshot to spot
// newly-seen hosts.
//
// Returns a non-nil empty map only when the router answered but had no entries;
// returns nil when the router is unreachable, doesn't speak SNMP, or neither OID
// yielded anything. The failure reason is NOT surfaced (use
// WalkRouterARPTableWithErr when observability matters); this variant keeps the
// best-effort contract the per-scan MAC-enrichment path relies on. ctx is
// currently unused (gosnmp's Walk takes no context); the timeout bounds the walk.
func WalkRouterARPTable(ctx context.Context, router, community string, timeout time.Duration) map[string]string {
	table, _ := walkRouterARPTable(ctx, router, community, timeout)
	return table
}

// WalkRouterARPTableWithErr is the observable variant of WalkRouterARPTable: it
// returns the same ip→mac map plus the error (if any) that caused the walk to
// fail or come back empty. Callers that need to log why a router yields nothing
// (e.g. the passive discovery source, which otherwise fails silently every poll)
// should prefer this. The map is non-nil-empty only on a successful walk that
// found zero entries; on any error it is nil.
func WalkRouterARPTableWithErr(ctx context.Context, router, community string, timeout time.Duration) (map[string]string, error) {
	return walkRouterARPTable(ctx, router, community, timeout)
}

// LookupMACViaRouters tries each router in turn until one returns a MAC for ip.
// This is the convenience wrapper the engine wires into the orchestrator's MAC
// resolver: it lets a deployment list several candidate routers and the first
// one that knows about ip wins. When cfg.Cred is set, the credential-aware path
// is used (v3 USM or a specific community); otherwise the legacy community path
// applies, preserving the passive discovery service's v1/v2c behavior.
func LookupMACViaRouters(ctx context.Context, cfg RouterARPConfig, ip string) (mac string, ok bool) {
	for _, r := range cfg.Routers {
		var found bool
		var m string
		if cfg.Cred != nil {
			m, found = LookupMACViaRouterCred(ctx, r, cfg.Cred, cfg.Timeout, ip)
		} else {
			m, found = LookupMACViaRouter(ctx, r, cfg.Community, cfg.Timeout, ip)
		}
		if found {
			return m, true
		}
	}
	return "", false
}

const routerARPCacheTTL = 30 * time.Second

// routerARPStore holds the per-router ARP table snapshot so a scan of N hosts
// behind one router only walks it once. The TTL is short (30s) so a long-running
// scan still sees fresh entries. Only the most-recently-queried router is
// cached (the common case is one router per subnet).
//
// The cache is keyed by (router, credKey) where credKey distinguishes the auth
// identity: for the legacy community path it's the community string; for a v3
// credential it's "v3:<id>:<user>" so two different v3 users on the same router
// don't share a (wrong) cache entry. The plaintext passphrase is NEVER part of
// the key (it would leak into the struct and logs).
type routerARPStore struct {
	router  string
	credKey string
	at      time.Time
	table   map[string]string
}

var routerARPCacheGlobal routerARPStore

// credKeyForCommunity returns the cache key for the legacy community path.
func credKeyForCommunity(community string) string {
	if community == "" {
		return "public"
	}
	return community
}

// credKeyForCredential returns the cache key for a v3 (or v1/v2c) credential.
// Uses the credential's DB id + username (stable, non-secret); the passphrase
// is deliberately excluded. An ad-hoc credential (id=0) is keyed by name so
// two ad-hoc credentials with the same user but different passphrases collide
// only if they also share a name — acceptable for a 30s best-effort cache.
func credKeyForCredential(c *scannerv2.SNMPCredential) string {
	if c.ID != 0 {
		return "cred:" + strconv.FormatInt(c.ID, 10) + ":" + c.UserName
	}
	return "ad-hoc:" + c.Name + ":" + c.UserName
}

// get returns the cached table for a router or walks it fresh when stale.
// Single-flight is intentionally omitted: the orchestrator resolves MAC
// sequentially per-host in the post-gather step, so there's no concurrency to
// guard here, and a redundant walk during a race is harmless (idempotent read).
func (s *routerARPStore) get(ctx context.Context, router, community string, timeout time.Duration) map[string]string {
	if router == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	credKey := credKeyForCommunity(community)
	if s.router == router && s.credKey == credKey &&
		time.Since(s.at) < routerARPCacheTTL && s.table != nil {
		return s.table
	}
	table, _ := walkRouterARPTable(ctx, router, community, timeout)
	if table == nil {
		return nil
	}
	s.router = router
	s.credKey = credKey
	s.at = time.Now()
	s.table = table
	return table
}

// getCred is the credential-aware cache lookup: it keys on the credential's
// stable identity (NOT the passphrase) and walks via walkRouterARPTableCred
// when stale. Same TTL + best-effort contract as get.
func (s *routerARPStore) getCred(router string, cred *scannerv2.SNMPCredential, timeout time.Duration) map[string]string {
	if router == "" || cred == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	credKey := credKeyForCredential(cred)
	if s.router == router && s.credKey == credKey &&
		time.Since(s.at) < routerARPCacheTTL && s.table != nil {
		return s.table
	}
	table, _ := walkRouterARPTableCred(router, cred, timeout)
	if table == nil {
		return nil
	}
	s.router = router
	s.credKey = credKey
	s.at = time.Now()
	s.table = table
	return table
}

// walkRouterARPTable walks both the legacy and RFC4293 ARP OIDs on router,
// returning a map of ip→lowercased-MAC plus the error (if any) that explains a
// nil/empty result. The map is nil on any error (connect failure, walk error);
// it is a non-nil empty map only when the router answered both OIDs cleanly but
// had zero entries. The caller's context bounds nothing here (gosnmp Walk has
// no context support); the snmp.Timeout on the client caps the walk.
//
// This is the legacy v1/v2c path. The credential-aware variant
// (walkRouterARPTableCred) routes through connectSNMP so a v3 credential works
// for cross-subnet MAC resolution too.
func walkRouterARPTable(_ context.Context, router, community string, timeout time.Duration) (map[string]string, error) {
	if community == "" {
		community = "public"
	}
	hint := scannerv2.ProbeHint{Community: community, Timeout: timeout}
	return walkRouterARPTableHint(router, hint, 1)
}

// walkRouterARPTableCred is the credential-aware variant: it builds a ProbeHint
// carrying the credential and delegates to walkRouterARPTableHint, which routes
// through connectSNMP (v3 USM when cred.IsV3(), else the credential's community).
func walkRouterARPTableCred(router string, cred *scannerv2.SNMPCredential, timeout time.Duration) (map[string]string, error) {
	hint := scannerv2.ProbeHint{Timeout: timeout, SNMPCredential: cred}
	return walkRouterARPTableHint(router, hint, 1)
}

// walkRouterARPTableHint is the shared walker: connect via connectSNMP (so any
// credential type works), then walk the legacy + RFC4293 ARP OIDs.
func walkRouterARPTableHint(router string, hint scannerv2.ProbeHint, retries int) (map[string]string, error) {
	snmp, err := connectSNMPWithRetries(router, hint, gosnmp.Version2c, retries)
	if err != nil {
		return nil, fmt.Errorf("snmp connect %s:161: %w", router, err)
	}
	defer snmp.Conn.Close()

	table := map[string]string{}
	// Try the legacy OID first (universally implemented on SNMP routers).
	if err := walkInto(snmp, oidIPNetToMediaPhysAddress, func(ip, mac string) {
		if ip != "" && mac != "" {
			table[ip] = mac
		}
	}); err != nil {
		return nil, fmt.Errorf("snmp walk %s %s: %w", router, oidIPNetToMediaPhysAddress, err)
	}
	// Fall back to / supplement with the RFC 4293 OID (covers IPv6 + newer
	// stacks). Don't overwrite legacy entries.
	if len(table) == 0 {
		if err := walkInto(snmp, oidIPNetToPhysicalAddress, func(ip, mac string) {
			if ip != "" && mac != "" {
				if _, exists := table[ip]; !exists {
					table[ip] = mac
				}
			}
		}); err != nil {
			return nil, fmt.Errorf("snmp walk %s %s: %w", router, oidIPNetToPhysicalAddress, err)
		}
	}
	if len(table) == 0 {
		// Router answered but neither OID yielded entries — not an error, just
		// an empty neighbour table. Return the (empty, non-nil) map so callers
		// can distinguish "answered, nothing to report" from "failed".
		return table, nil
	}
	return table, nil
}

// walkInto runs a Walk on oid and calls emit for each (ip, mac) pair. The OID
// index encodes the IP: the trailing path components after the prefix are
// either an IPv4 (4 decimal octets) or a length-prefixed address octet string.
// gosnmp hands us pdu.Name as the full dotted path including the index.
//
// Returns the walk error instead of swallowing it: a connection-refused or
// timeout surfaces here so callers can log WHY a router yields nothing.
// The caller's context is intentionally not forwarded: gosnmp's Walk doesn't
// accept one, and the snmp.Timeout set on the client bounds the run.
func walkInto(snmp *gosnmp.GoSNMP, oid string, emit func(ip, mac string)) error {
	return snmp.Walk(oid, func(pdu gosnmp.SnmpPDU) error {
		ip := indexToIP(pdu.Name, oid)
		mac := snmpOctetsToMAC(pdu.Value)
		if ip != "" && mac != "" {
			emit(ip, mac)
		}
		return nil
	})
}

// indexToIP extracts the IPv4 address from a varbind name like
// ".1.3.6.1.2.1.4.22.1.2.2.192.168.63.133" where the trailing 4 components
// after the ifIndex are the IP octets. Returns "" when the trailing path isn't
// a recognizable IPv4 index. Tolerates leading-dot differences between the OID
// prefix (no dot) and the gosnmp-returned pdu.Name (leading dot).
func indexToIP(fullOID, prefix string) string {
	// Normalize both to no leading dot so TrimPrefix matches.
	f := strings.TrimPrefix(fullOID, ".")
	p := strings.TrimPrefix(prefix, ".")
	tail := strings.TrimPrefix(f, p)
	if tail == f {
		return "" // prefix didn't match
	}
	tail = strings.TrimPrefix(tail, ".")
	parts := strings.Split(tail, ".")
	// ipNetToMedia index = ifIndex.ip[0].ip[1].ip[2].ip[3] → ≥5 parts
	if len(parts) < 5 {
		return ""
	}
	ipParts := parts[len(parts)-4:]
	ip := strings.Join(ipParts, ".")
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

// snmpOctetsToMAC converts a gosnmp varbind value (a []byte of 6 octets for a
// MAC) into the canonical lowercase "aa:bb:cc:dd:ee:ff" form. Returns "" for
// anything that isn't exactly 6 octets.
func snmpOctetsToMAC(v any) string {
	b, ok := v.([]byte)
	if !ok || len(b) != 6 {
		return ""
	}
	return formatMAC(b)
}

// formatMAC formats 6 bytes as "aa:bb:cc:dd:ee:ff".
func formatMAC(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 17)
	for i, octet := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[octet>>4], hex[octet&0x0f])
	}
	return string(out)
}
