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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HostapdSource enumerates the WiFi stations (STAs) currently associated to the
// local AP(s) and emits a NewHostEvent per STA. It is a router-resident signal:
// only the WiFi AP itself (a router running hostapd) sees the association list
// - signal strength, link rate, SSID, and connect time are GOLD for device
// tracking (room-level location via signal, WiFi device identification, rogue-
// AP detection) and completely unavailable to a wired host-based scanner.
//
// Why it matters (Tier-1 router-only signal, see
// docs/private/architecture-debt-and-openwrt-2026-07-27.md §3.2):
//
//   - Sees WiFi-only devices that may never answer L3 probes (smart-home
//     sensors, sleep-aggressive phones, guests on the WiFi-only segment).
//   - MAC-authoritative at association time → feeds the device-bridge's MAC-
//     primary identity path even before any IP-level probe runs.
//
// Two backends, in priority order (per the design decision, both supported,
// hostapd first):
//
//  1. hostapd_ctrl socket (preferred). Opens the hostapd control interface
//     (a UNIX datagram socket at /var/run/hostapd/<phy>, the OpenWrt/consumer-
//     router convention) and sends STA-FIRST / STA-NEXT to walk the association
//     table. Most authoritative, gets signal dBm, connect time, RX/TX bytes,
//     SSID, and has zero subprocess overhead.
//
//  2. `iw station dump` fallback. Shells `iw dev <wlan> station dump` (iw ships
//     with every wireless host including OpenWrt/Debian/Arch) and parses the
//     human-readable output. Slightly less detail (no SSID/connect-time), and
//     forks a subprocess per sweep, but works without a readable hostapd ctrl
//     socket (e.g. when the agent runs alongside an AP it doesn't own the
//     hostapd process of, or when hostapd ctrl_interface is disabled).
//
// The source tries hostapd first per sweep; on any error (socket missing,
// permission denied, no STAs) it falls back to iw for the same interfaces.
// When neither yields anything (no WiFi, no hostapd, no iw) it no-ops, same
// graceful pattern as the other router sources.
//
// Operator config: scanner.discovery.hostapd.interfaces lists the wlan names to
// poll (e.g. ["wlan0"]). When empty the source probes the conventional
// /var/run/hostapd/* sockets + a small default iface list (wlan0).
type HostapdSource struct {
	interfaces []string // wlan names, e.g. ["wlan0"]; empty = autodetect
	ctrlDir    string   // hostapd ctrl_interface dir (default /var/run/hostapd)
	interval   time.Duration
	svc        *Service
	logger     *slog.Logger

	// wifiNeighborSink, when set, receives one callback per AP interface per
	// sweep with the FULL currently-associated STA MAC list and the AP's own
	// interface identity (#505). The full-list refresh (not just new STAs) is
	// deliberate: the caller persists AP→STA edges whose last_seen must track
	// the association's lifetime.
	wifiNeighborSink func(apMAC, iface string, staMACs []string)

	mu       sync.Mutex
	previous map[string]bool // mac set, last sweep: for diff
}

// NewHostapdSource constructs the source. interfaces is the wlan name list;
// when empty the source autodetects at sweep time (probes /var/run/hostapd/* +
// falls back to "wlan0" for iw). ctrlDir overrides the hostapd ctrl_interface
// path (rarely needed; OpenWrt/Asuswrt use the default /var/run/hostapd).
func NewHostapdSource(interfaces []string, interval time.Duration, svc *Service, logger *slog.Logger) *HostapdSource {
	if logger == nil {
		logger = slog.Default()
	}
	if len(interfaces) == 0 {
		// Default iface list for the iw fallback. hostapd-ctrl path discovers
		// sockets by glob, so this only affects iw.
		interfaces = []string{"wlan0"}
	}
	return &HostapdSource{
		interfaces: interfaces,
		ctrlDir:    "/var/run/hostapd",
		interval:   interval,
		svc:        svc,
		logger:     logger,
		previous:   map[string]bool{},
	}
}

// Start launches the poll goroutine (immediate first sweep, then ticks).
func (s *HostapdSource) Start(ctx context.Context) {
	go s.loop(ctx)
}

func (s *HostapdSource) loop(ctx context.Context) {
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

// sweep enumerates associated STAs via hostapd-ctrl first, falling back to iw
// when hostapd yields nothing.
func (s *HostapdSource) sweep() {
	stas := s.readViaHostapdCtrl()
	if len(stas) == 0 {
		// hostapd didn't yield anything (no sockets, no perms, or no STA on those
		// sockets), try iw station dump as the fallback. Either backend failing
		// is normal on a non-router host; both failing is the no-op case.
		stas = s.readViaIW()
	}
	s.sweepWith(stas)
}

// SetWifiNeighborSink registers the AP→STA edge callback (#505). apMAC is the
// AP interface's own MAC (resolved via net.InterfaceByName at call time, so a
// renamed/added interface is picked up without restart); an interface that
// cannot be resolved yields apMAC "" and the caller decides (the persist path
// skips unknown local MACs by design). Nil clears the callback.
func (s *HostapdSource) SetWifiNeighborSink(fn func(apMAC, iface string, staMACs []string)) {
	s.wifiNeighborSink = fn
}

// sweep diffs a freshly gathered mac→staInfo snapshot against the previous
// sweep and emits one event per newly-seen MAC. Split from sweep so tests can
// drive the diff/emit path directly (same seam as ARPCacheSource.sweepWith).
func (s *HostapdSource) sweepWith(stas map[string]staInfo) {
	if len(stas) == 0 {
		return
	}

	current := make(map[string]bool, len(stas))
	for mac := range stas {
		current[mac] = true
	}

	s.mu.Lock()
	prev := s.previous
	s.previous = current
	s.mu.Unlock()

	for mac, info := range stas {
		if prev[mac] {
			continue
		}
		hints := map[string]string{"discovery_note": "wifi_assoc"}
		if info.signal != "" {
			hints["wifi_signal_dbm"] = info.signal
		}
		if info.ssid != "" {
			hints["wifi_ssid"] = info.ssid
		}
		if info.connectTime != "" {
			hints["wifi_connected_secs"] = info.connectTime
		}
		s.svc.Emit(NewHostEvent{
			MAC:    mac,
			Source: "hostapd",
			// No IP: WiFi association is L2. handle() routes MAC-only events to
			// the enrich-only path: a known MAC gets the WiFi telemetry below
			// merged into scan_attributes, and an ARP/DHCP/scan sighting of the
			// same MAC fills the IP. An unknown MAC is dropped (no device is
			// fabricated for a MAC with no L3 sighting).
			Hints: hints,
		})
	}

	// AP→STA edges (#505): report every currently-associated STA grouped by AP
	// interface. Runs on the source's own sweep goroutine; the caller's
	// persist path only writes device_neighbors in short transactions (the
	// #501 sink contract), so it cannot interleave with the coordinator's
	// serialized device upserts.
	if s.wifiNeighborSink != nil {
		byIface := map[string][]string{}
		for mac, info := range stas {
			if info.iface == "" {
				continue
			}
			byIface[info.iface] = append(byIface[info.iface], mac)
		}
		for iface, macs := range byIface {
			apMAC, err := ifaceMAC(iface)
			if err != nil {
				s.logger.Debug("discovery: hostapd AP iface MAC unavailable",
					"iface", iface, "error", err)
			}
			s.wifiNeighborSink(apMAC, iface, macs)
		}
	}
}

// staInfo holds the optional per-STA details each backend may capture. Only MAC
// is required; the rest are optional enrichment hints. iface records which AP
// interface the association was seen on (the ctrl-socket name, or the iw dev
// interface) — it attributes the AP side of the #505 edge.
type staInfo struct {
	mac         string
	iface       string // AP-side interface the STA is associated to
	signal      string // dBm, e.g. "-42"
	ssid        string
	connectTime string // seconds connected
}

// readViaHostapdCtrl walks the hostapd control sockets in s.ctrlDir and emits
// one staInfo per associated station. Returns nil/empty on any error (caller
// falls back to iw). Uses the hostapd_cli protocol over a connected UNIX
// datagram socket: ATTACH (optional), STA-FIRST, then STA-NEXT until "FAIL".
func (s *HostapdSource) readViaHostapdCtrl() map[string]staInfo {
	out := map[string]staInfo{}
	// Glob the ctrlDir for socket files, each phy/AP has one (e.g.
	// /var/run/hostapd/wlan0, /var/run/hostapd-phy1.conf on some builds).
	patterns := []string{s.ctrlDir + "/*"}
	for _, pat := range patterns {
		matches, _ := ctrlSocketGlob(pat)
		for _, sockPath := range matches {
			stas := s.queryHostapdSocket(sockPath)
			for mac, info := range stas {
				out[mac] = info
			}
		}
	}
	return out
}

// queryHostapdSocket opens ONE hostapd ctrl socket, sends STA-FIRST/STA-NEXT,
// and returns the parsed stations. Errors are tolerated (logged at debug) and
// return empty so the caller can try the next socket or fall back to iw.
func (s *HostapdSource) queryHostapdSocket(sockPath string) map[string]staInfo {
	// Bind the client to an abstract address before exchanging. hostapd (and
	// any datagram server) replies with sendto() to the address it received
	// from; a nameless peer — what a plain net.Dial yields on Linux — is
	// unrepliable, so every response would be dropped. Found live on the rig
	// (#505): the ctrl path was silently deaf against a real protocol server,
	// only the iw fallback ever produced data.
	raddr, err := net.ResolveUnixAddr("unixgram", sockPath)
	if err != nil {
		s.logger.Debug("discovery: hostapd ctrl socket path invalid", "socket", sockPath, "error", err)
		return nil
	}
	laddr, _ := net.ResolveUnixAddr("unixgram",
		fmt.Sprintf("@mibee-hostapd-%d-%d", os.Getpid(), time.Now().UnixNano()))
	conn, err := net.DialUnix("unixgram", laddr, raddr)
	if err != nil {
		s.logger.Debug("discovery: hostapd ctrl socket dial failed", "socket", sockPath, "error", err)
		return nil
	}
	defer conn.Close()
	// Set a short read deadline so a non-responsive socket doesn't stall the
	// sweep loop. hostapd responds to STA-* in milliseconds.
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil
	}

	stas := map[string]staInfo{}
	// The ctrl socket's file name is the AP interface (hostapd convention:
	// one socket per phy, named after the interface). Attribution for the
	// #505 AP→STA edge.
	iface := filepath.Base(sockPath)
	// STA-FIRST → first station; then STA-NEXT <mac> → next after that, until FAIL.
	cmd := "STA-FIRST"
	for {
		if _, err := conn.Write([]byte(cmd)); err != nil {
			return stas
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return stas
		}
		resp := string(buf[:n])
		if strings.HasPrefix(resp, "FAIL") || resp == "" {
			return stas // no more stations (or none at all on STA-FIRST)
		}
		info := parseHostapdSTA(resp)
		if info.mac != "" {
			info.iface = iface
			stas[info.mac] = info
			cmd = "STA-NEXT " + info.mac
		} else {
			return stas
		}
	}
}

// parseHostapdSTA parses the key=value lines of one hostapd STA-FIRST/STA-NEXT
// reply. Each line is "key=value"; the keys we care about: addr, signal,
// connected_time, ssid.
func parseHostapdSTA(resp string) staInfo {
	info := staInfo{}
	for _, line := range strings.Split(resp, "\n") {
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		k, v := line[:eq], line[eq+1:]
		switch k {
		case "addr":
			info.mac = strings.ToLower(v)
		case "signal":
			info.signal = v
		case "connected_time":
			info.connectTime = v
		case "ssid":
			info.ssid = v
		}
	}
	return info
}

// readViaIW runs `iw dev <iface> station dump` for each configured interface and
// parses the human-readable blocks (one per STA, MAC in the header line, key=
// value details indented).
func (s *HostapdSource) readViaIW() map[string]staInfo {
	out := map[string]staInfo{}
	for _, iface := range s.interfaces {
		stas := s.queryIW(iface)
		for mac, info := range stas {
			out[mac] = info
		}
	}
	return out
}

// queryIW runs iw once for one interface and parses the station dump. Errors are
// tolerated (iw absent / iface down / not root) and return empty.
func (s *HostapdSource) queryIW(iface string) map[string]staInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "iw", "dev", iface, "station", "dump")
	out, err := cmd.Output()
	if err != nil {
		s.logger.Debug("discovery: iw station dump failed", "iface", iface, "error", err)
		return nil
	}
	stas := parseIWStationDump(string(out))
	// Backfill AP attribution when the dump header lacked "(on <iface>)" (#505).
	for mac, info := range stas {
		if info.iface == "" {
			info.iface = iface
			stas[mac] = info
		}
	}
	return stas
}

// parseIWStationDump parses `iw dev X station dump` output into a mac→staInfo
// map. Format (one block per station, key=value lines indented):
//
//	Station aa:bb:cc:dd:ee:ff (on wlan0)
//	        inactive time:    120 ms
//	        rx bytes:         12345
//	        signal:           -42 dBm
//	        ...
func parseIWStationDump(out string) map[string]staInfo {
	stas := map[string]staInfo{}
	var cur *staInfo
	flush := func() {
		if cur != nil && cur.mac != "" {
			stas[cur.mac] = *cur
		}
		cur = nil
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Station ") {
			flush()
			// "Station <mac> (on <iface>)"
			mac := extractIWStationMAC(line)
			iface := extractIWStationIface(line)
			if mac != "" {
				cur = &staInfo{mac: mac, iface: iface}
			}
			continue
		}
		if cur == nil {
			continue
		}
		// Indented "key:           value" detail lines.
		trim := strings.TrimSpace(line)
		if v := iwValue(trim, "signal:"); v != "" {
			// "signal:   -42 dBm" → keep "-42"
			cur.signal = strings.TrimSpace(strings.TrimSuffix(v, "dBm"))
		}
	}
	flush()
	return stas
}

// extractIWStationMAC pulls the MAC out of a "Station <mac> (on <iface>)" line.
func extractIWStationMAC(line string) string {
	const prefix = "Station "
	if !strings.HasPrefix(line, prefix) {
		return ""
	}
	rest := line[len(prefix):]
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		rest = rest[:sp]
	}
	return strings.ToLower(rest)
}

// extractIWStationIface pulls the AP interface out of a
// "Station <mac> (on <iface>)" header, falling back to the queried interface
// name when the dump omits the "(on ...)" part (some iw builds do).
func extractIWStationIface(line string) string {
	open := strings.Index(line, "(on ")
	if open < 0 {
		return ""
	}
	rest := line[open+4:]
	if sp := strings.IndexByte(rest, ')'); sp >= 0 {
		return rest[:sp]
	}
	return ""
}

// iwValue returns the value portion of a "key:   value" line when line starts
// with key; "" otherwise.
func iwValue(line, key string) string {
	if !strings.HasPrefix(line, key) {
		return ""
	}
	return strings.TrimSpace(line[len(key):])
}

// ctrlSocketGlob lists hostapd ctrl socket paths matching the glob pattern,
// skipping obvious non-sockets (directories, the global ctrl dir itself). Kept
// minimal, on a real AP the dir contains one datagram socket per phy.
func ctrlSocketGlob(pattern string) ([]string, error) {
	// filepath.Glob lists names; the caller's Dial rejects non-sockets.
	return filepath.Glob(pattern)
}

// String returns a debug label for the source.
func (s *HostapdSource) String() string {
	return fmt.Sprintf("hostapd(interfaces=%v,ctrl=%s)", s.interfaces, s.ctrlDir)
}
