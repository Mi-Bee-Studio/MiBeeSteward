package probe

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
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

// WalkRouterARPTable walks a single router's SNMP ARP table (ipNetToMediaPhysAddress,
// falling back to the RFC 4293 ipNetToPhysicalPhysAddress) and returns the full
// ip→lowercased-MAC map. It is the exported counterpart to the unexported
// walkRouterARP used internally for per-host MAC resolution: the long-running
// passive discovery service walks the WHOLE table (once per router, on a timer)
// to diff against its previous snapshot and spot newly-seen hosts.
//
// Returns a non-nil empty map only when the router answered but had no entries;
// returns nil when the router is unreachable, doesn't speak SNMP, or neither OID
// yielded anything. ctx is currently unused (gosnmp's Walk takes no context); the
// timeout bounds the walk.
func WalkRouterARPTable(ctx context.Context, router, community string, timeout time.Duration) map[string]string {
	return walkRouterARP(ctx, router, community, timeout)
}

// LookupMACViaRouters tries each router in turn until one returns a MAC for ip.
// This is the convenience wrapper the engine wires into the orchestrator's MAC
// resolver: it lets a deployment list several candidate routers and the first
// one that knows about ip wins.
func LookupMACViaRouters(ctx context.Context, cfg RouterARPConfig, ip string) (mac string, ok bool) {
	for _, r := range cfg.Routers {
		if m, found := LookupMACViaRouter(ctx, r, cfg.Community, cfg.Timeout, ip); found {
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
type routerARPStore struct {
	router string
	comm   string
	at     time.Time
	table  map[string]string
}

var routerARPCacheGlobal routerARPStore

// get returns the cached table for a router or walks it fresh when stale.
// Single-flight is intentionally omitted: the orchestrator resolves MAC
// sequentially per-host in the post-gather step, so there's no concurrency to
// guard here, and a redundant walk during a race is harmless (idempotent read).
func (s *routerARPStore) get(ctx context.Context, router, community string, timeout time.Duration) map[string]string {
	if router == "" {
		return nil
	}
	if community == "" {
		community = "public"
	}
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	if s.router == router && s.comm == community &&
		time.Since(s.at) < routerARPCacheTTL && s.table != nil {
		return s.table
	}
	table := walkRouterARP(ctx, router, community, timeout)
	if table == nil {
		return nil
	}
	s.router = router
	s.comm = community
	s.at = time.Now()
	s.table = table
	return table
}

// walkRouterARP walks both the legacy and RFC4293 ARP OIDs on router, returning
// a map of ip→lowercased-MAC. Returns nil if neither OID yields anything. The
// caller's context bounds nothing here (gosnmp Walk has no context support);
// the snmp.Timeout on the client caps the walk.
func walkRouterARP(_ context.Context, router, community string, timeout time.Duration) map[string]string {
	snmp := &gosnmp.GoSNMP{
		Target:    router,
		Port:      161,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   1,
	}
	if err := snmp.Connect(); err != nil {
		return nil
	}
	defer snmp.Conn.Close()

	table := map[string]string{}
	// Try the legacy OID first (universally implemented on SNMP routers).
	walkInto(snmp, oidIPNetToMediaPhysAddress, func(ip, mac string) {
		if ip != "" && mac != "" {
			table[ip] = mac
		}
	})
	// Fall back to / supplement with the RFC 4293 OID (covers IPv6 + newer
	// stacks). Don't overwrite legacy entries.
	if len(table) == 0 {
		walkInto(snmp, oidIPNetToPhysicalAddress, func(ip, mac string) {
			if ip != "" && mac != "" {
				if _, exists := table[ip]; !exists {
					table[ip] = mac
				}
			}
		})
	}
	if len(table) == 0 {
		return nil
	}
	return table
}

// walkInto runs a Walk on oid and calls emit for each (ip, mac) pair. The OID
// index encodes the IP: the trailing path components after the prefix are
// either an IPv4 (4 decimal octets) or a length-prefixed address octet string.
// gosnmp hands us pdu.Name as the full dotted path including the index.
//
// The caller's context is intentionally not forwarded: gosnmp's Walk doesn't
// accept one, and the snmp.Timeout set on the client bounds the run.
func walkInto(snmp *gosnmp.GoSNMP, oid string, emit func(ip, mac string)) {
	walkErr := snmp.Walk(oid, func(pdu gosnmp.SnmpPDU) error {
		ip := indexToIP(pdu.Name, oid)
		mac := snmpOctetsToMAC(pdu.Value)
		if ip != "" && mac != "" {
			emit(ip, mac)
		}
		return nil
	})
	_ = walkErr
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
