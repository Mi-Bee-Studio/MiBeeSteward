package runner

import (
	"bufio"
	"context"
	"database/sql"
	"os"
	"strconv"
	"strings"
	"time"

	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/store"
)

// routeTablePath is the kernel's routing table. The default route row
// (Destination=00000000) tells us the gateway IP for the scanner's subnet.
// Like /proc/net/arp it is world-readable (no privileges needed).
const routeTablePath = "/proc/net/route"

// injectARPTopology is the post-scan step that derives L2 adjacency edges from
// the local kernel's ARP cache — the ONLY topology data source available when
// no device on the network speaks SNMP (Bridge-MIB / LLDP-MIB both need SNMP).
//
// In home/SOHO networks without managed switches, /proc/net/arp is the sole
// source of "who is on this subnet" data. It cannot tell us which physical
// switch port a device sits behind (that needs Bridge-MIB), but it CAN tell us
// "every device on this subnet reaches the rest of the network through the
// default gateway" — a meaningful logical topology that the L2 graph view can
// render as a gateway-centric star.
//
// The edges it writes use protocol="ARP" to distinguish them from the
// physical-port edges produced by LLDP ("LLDP") and Bridge-MIB ("Bridge-MIB").
// The frontend renders ARP edges as grey dashed lines (logical adjacency)
// vs solid colored lines for physical adjacency.
//
// Runs once per local scan, after all hosts are persisted (so device_id
// lookups succeed). Agent scans do NOT call this — each agent injects its own
// ARP edges from its own /proc/net/arp, then the center merges them via the
// existing ApplyReport path. Best-effort: failures are logged, never abort a
// scan (same pattern as DetectLost).
func (rn *Runner) injectARPTopology(ctx context.Context, networkID sql.NullInt64, reports []scannerv2.HostReport) {
	if !networkID.Valid {
		return // no network scoping — can't partition edges correctly
	}

	// 1. Read the ARP table (ip → mac).
	arpEntries, err := readLocalARP()
	if err != nil || len(arpEntries) == 0 {
		if err != nil {
			rn.logger.Debug("arp-topology: read /proc/net/arp failed", "error", err)
		}
		return
	}

	// 2. Identify the gateway: prefer /proc/net/route default route, fall back
	//    to .1 heuristic on the scanner's own subnet.
	gatewayIP := readDefaultGateway()
	if gatewayIP == "" {
		gatewayIP = guessGatewayFromARP(arpEntries)
	}
	if gatewayIP == "" {
		rn.logger.Debug("arp-topology: no gateway identified, skipping")
		return
	}
	gatewayMAC, ok := arpEntries[gatewayIP]
	if !ok || gatewayMAC == "" {
		rn.logger.Debug("arp-topology: gateway has no ARP entry", "gateway", gatewayIP)
		return
	}

	// 3. Collect MACs from this scan's alive reports (only devices that were
	//    actually scanned get ARP edges — not every kernel cache straggler).
	scannedMACs := make(map[string]bool, len(reports))
	for _, rep := range reports {
		if !rep.Alive {
			continue
		}
		if mac := reportMAC(rep); mac != "" {
			scannedMACs[mac] = true
		}
	}
	if len(scannedMACs) == 0 {
		return
	}

	// 4. Batch-upsert ARP edges: device → gateway_mac for every scanned device
	//    EXCEPT the gateway itself (a device shouldn't be its own neighbor).
	//    Each edge resolves device by MAC in devices table (MAC-primary upsert
	//    key), then upserts into device_neighbors on (device_id, gateway_mac,
	//    "ARP").
	gwMACNorm := store.NormalizeMAC(gatewayMAC)
	if gwMACNorm == "" {
		return
	}

	tx, err := rn.dbConn.BeginTx(ctx, nil)
	if err != nil {
		rn.logger.Debug("arp-topology: begin tx failed", "error", err)
		return
	}
	defer tx.Rollback() //nolint:errcheck

	now := time.Now().UTC()
	netID := networkID.Int64
	inserted := 0

	for mac := range scannedMACs {
		if mac == gwMACNorm {
			continue // gateway to itself — skip
		}

		var deviceID int64
		err := tx.QueryRowContext(ctx,
			`SELECT id FROM devices WHERE mac_address = ? AND (network_id = ? OR network_id IS NULL) LIMIT 1`,
			mac, netID).Scan(&deviceID)
		if err != nil {
			continue // device not persisted yet or MAC mismatch — skip silently
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO device_neighbors (device_id, neighbor_mac, protocol, local_port, remote_port, network_id, first_seen, last_seen)
			VALUES (?, ?, 'ARP', '', '', ?, ?, ?)
			ON CONFLICT(device_id, neighbor_mac, protocol) DO UPDATE SET
				last_seen = excluded.last_seen`,
			deviceID, gwMACNorm, netID, now, now)
		if err != nil {
			rn.logger.Debug("arp-topology: upsert edge failed", "mac", mac, "error", err)
			continue
		}
		inserted++
	}

	if err := tx.Commit(); err != nil {
		rn.logger.Debug("arp-topology: commit failed", "error", err)
		return
	}

	if inserted > 0 {
		rn.logger.Info("arp-topology: injected ARP adjacency edges",
			"network_id", netID, "gateway", gatewayIP, "edges", inserted)
	}
}

// readLocalARP parses /proc/net/arp into an ip→lowercased-mac map. Entries with
// incomplete (zero) MACs are skipped. This mirrors probe.parseARPFile but lives
// here to avoid importing the probe package (which would create a cycle through
// the engine).
func readLocalARP() (map[string]string, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make(map[string]string)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4*1024), 64*1024)
	first := true
	for scanner.Scan() {
		if first {
			first = false // skip header
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		ip, mac := fields[0], fields[3]
		if mac == "" || strings.HasPrefix(mac, "00:00:00:00:00:00") {
			continue
		}
		out[ip] = strings.ToLower(mac)
	}
	return out, scanner.Err()
}

// readDefaultGateway parses /proc/net/route and returns the default gateway IP
// (the gateway of the row whose Destination is 00000000). /proc/net/route stores
// IPs and masks in hex little-endian (e.g. "0100A8C0" = 192.168.0.1). Returns
// "" when no default route exists or the file can't be read (non-Linux / tests).
func readDefaultGateway() string {
	f, err := os.Open(routeTablePath)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4*1024), 64*1024)
	first := true
	for scanner.Scan() {
		if first {
			first = false // skip header: Iface Destination Gateway Flags ...
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		if fields[1] != "00000000" {
			continue // not the default route
		}
		return hexRouteToIP(fields[2])
	}
	return ""
}

// hexRouteToIP converts a /proc/net/route hex little-endian field to a dotted
// IPv4 string. "0100A8C0" → "192.168.0.1". Returns "" on malformed input.
func hexRouteToIP(hex string) string {
	if len(hex) != 8 {
		return ""
	}
	b0, err1 := strconv.ParseUint(hex[6:8], 16, 8)
	b1, err2 := strconv.ParseUint(hex[4:6], 16, 8)
	b2, err3 := strconv.ParseUint(hex[2:4], 16, 8)
	b3, err4 := strconv.ParseUint(hex[0:2], 16, 8)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return ""
	}
	return strconv.FormatUint(b0, 10) + "." +
		strconv.FormatUint(b1, 10) + "." +
		strconv.FormatUint(b2, 10) + "." +
		strconv.FormatUint(b3, 10)
}

// guessGatewayFromARP finds a likely gateway IP from the ARP entries when
// /proc/net/route is unavailable. Heuristic: the .1 address of the first /24
// seen in the ARP table (e.g. 192.168.63.1). Returns "" if no .1 exists.
func guessGatewayFromARP(arp map[string]string) string {
	for ip := range arp {
		parts := strings.Split(ip, ".")
		if len(parts) == 4 && parts[3] == "1" {
			return ip
		}
	}
	return ""
}
